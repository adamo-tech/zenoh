//
// Copyright (c) 2023 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//

#[cfg(all(feature = "uring", target_os = "linux"))]
use std::os::fd::RawFd;
use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::RwLock as AsyncRwLock;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use web_transport_quinn::{RecvStream, Request, SendStream, Session, ALPN};
use zenoh_core::{zasynclock, zasyncread, zasyncwrite};
use zenoh_link_commons::{
    get_ip_interface_names,
    quic::{
        get_quic_addr, get_quic_host, unicast::QuicConnection, TlsClientConfig, TlsServerConfig,
    },
    LinkAuthId, LinkManagerUnicastTrait, LinkUnicast, LinkUnicastTrait, NewLinkChannelSender,
};
use zenoh_protocol::{
    core::{EndPoint, Locator, Priority},
    transport::BatchSize,
};
#[cfg(all(feature = "uring", target_os = "linux"))]
use zenoh_result::bail;
use zenoh_result::{zerror, ZResult};

use super::{handoff, WEBTRANSPORT_DEFAULT_MTU, WEBTRANSPORT_LOCATOR_PREFIX};

pub struct LinkUnicastWebTransport {
    session: Session,
    send: AsyncMutex<SendStream>,
    recv: AsyncMutex<RecvStream>,
    src_addr: SocketAddr,
    src_locator: Locator,
    dst_addr: SocketAddr,
    dst_locator: Locator,
    auth_id: LinkAuthId,
    /// Present for handed-off sessions, whose delivery is tracked.
    connection: Option<QuicConnection>,
    is_mixed_rel: bool,
}

impl LinkUnicastWebTransport {
    pub(crate) fn new(
        session: Session,
        send: SendStream,
        recv: RecvStream,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
    ) -> Self {
        Self {
            session,
            send: AsyncMutex::new(send),
            recv: AsyncMutex::new(recv),
            src_addr,
            src_locator: Locator::new(WEBTRANSPORT_LOCATOR_PREFIX, src_addr.to_string(), "")
                .unwrap(),
            dst_addr,
            dst_locator: Locator::new(WEBTRANSPORT_LOCATOR_PREFIX, dst_addr.to_string(), "")
                .unwrap(),
            auth_id: LinkAuthId::WebTransport,
            connection: None,
            is_mixed_rel: false,
        }
    }

    pub(crate) fn tracked(
        session: Session,
        send: SendStream,
        recv: RecvStream,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        connection: QuicConnection,
        is_mixed_rel: bool,
    ) -> Self {
        let mut link = Self::new(session, send, recv, src_addr, dst_addr);
        link.connection = Some(connection);
        link.is_mixed_rel = is_mixed_rel;
        link
    }
}

#[async_trait]
impl LinkUnicastTrait for LinkUnicastWebTransport {
    async fn close(&self) -> ZResult<()> {
        tracing::trace!("Closing WebTransport link: {}", self);
        self.session.close(0, b"close");
        Ok(())
    }

    async fn write(&self, buffer: &[u8], _priority: Option<Priority>) -> ZResult<usize> {
        let mut guard = zasynclock!(self.send);
        guard.write(buffer).await.map_err(|e| {
            let e = zerror!("Write error on WebTransport link {}: {}", self, e);
            tracing::trace!("{}", &e);
            e.into()
        })
    }

    async fn write_all(&self, buffer: &[u8], _priority: Option<Priority>) -> ZResult<()> {
        let mut guard = zasynclock!(self.send);
        guard.write_all(buffer).await.map_err(|e| {
            let e = zerror!("Write error on WebTransport link {}: {}", self, e);
            tracing::trace!("{}", &e);
            e.into()
        })
    }

    async fn read(&self, buffer: &mut [u8], _priority: Option<Priority>) -> ZResult<usize> {
        let mut guard = zasynclock!(self.recv);
        guard
            .read(buffer)
            .await
            .map_err(|e| {
                let e = zerror!("Read error on WebTransport link {}: {}", self, e);
                tracing::trace!("{}", &e);
                zenoh_result::Error::from(e)
            })?
            .ok_or_else(|| {
                let e = zerror!("Read error on WebTransport link {}: stream finished", self);
                tracing::trace!("{}", &e);
                e.into()
            })
    }

    async fn read_exact(&self, buffer: &mut [u8], _priority: Option<Priority>) -> ZResult<()> {
        let mut guard = zasynclock!(self.recv);
        guard.read_exact(buffer).await.map_err(|e| {
            let e = zerror!("Read error on WebTransport link {}: {}", self, e);
            tracing::trace!("{}", &e);
            e.into()
        })
    }

    #[inline(always)]
    fn get_src(&self) -> &Locator {
        &self.src_locator
    }

    #[inline(always)]
    fn get_dst(&self) -> &Locator {
        &self.dst_locator
    }

    #[inline(always)]
    fn get_mtu(&self) -> BatchSize {
        *WEBTRANSPORT_DEFAULT_MTU
    }

    #[inline(always)]
    fn get_interface_names(&self) -> Vec<String> {
        get_ip_interface_names(&self.src_addr)
    }

    fn get_quic_packet_observer(&self) -> Option<zenoh_link_commons::PacketObserverHandle> {
        self.connection
            .as_ref()
            .map(QuicConnection::packet_observer)
    }

    fn get_quic_stats(&self) -> Option<zenoh_link_commons::QuicStats> {
        self.connection
            .as_ref()
            .map(|connection| connection.stats(true, false, self.is_mixed_rel))
    }

    #[inline(always)]
    fn is_reliable(&self) -> bool {
        super::IS_RELIABLE
    }

    #[inline(always)]
    fn is_streamed(&self) -> bool {
        true
    }

    #[inline(always)]
    fn get_auth_id(&self) -> &LinkAuthId {
        &self.auth_id
    }

    #[cfg(all(feature = "uring", target_os = "linux"))]
    fn get_fd(&self) -> ZResult<RawFd> {
        bail!("Not supported");
    }

    #[inline(always)]
    fn supports_priorities(&self) -> bool {
        false
    }
}

impl Drop for LinkUnicastWebTransport {
    fn drop(&mut self) {
        self.session.close(0, b"dropped");
    }
}

impl fmt::Display for LinkUnicastWebTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} => {}", self.src_addr, self.dst_addr)
    }
}

impl fmt::Debug for LinkUnicastWebTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebTransport")
            .field("src", &self.src_addr)
            .field("dst", &self.dst_addr)
            .finish()
    }
}

/*************************************/
/*            MANAGER                */
/*************************************/
struct ListenerUnicastWebTransport {
    endpoint: EndPoint,
    token: CancellationToken,
    handle: JoinHandle<ZResult<()>>,
}

pub struct LinkManagerUnicastWebTransport {
    manager: NewLinkChannelSender,
    listeners: Arc<AsyncRwLock<HashMap<SocketAddr, ListenerUnicastWebTransport>>>,
    handoff_listeners: Arc<AsyncRwLock<HashMap<String, ListenerUnicastWebTransport>>>,
}

impl fmt::Debug for LinkManagerUnicastWebTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkManagerUnicastWebTransport")
            .finish_non_exhaustive()
    }
}

impl LinkManagerUnicastWebTransport {
    pub fn new(manager: NewLinkChannelSender) -> Self {
        Self {
            manager,
            listeners: Arc::new(AsyncRwLock::new(HashMap::new())),
            handoff_listeners: Arc::new(AsyncRwLock::new(HashMap::new())),
        }
    }
}

// Build the CONNECT url, bracketing bare IPv6 hosts.
fn connect_url(host: &str, port: u16) -> ZResult<url::Url> {
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    url::Url::parse(&format!("https://{host}:{port}"))
        .map_err(|e| zerror!("Invalid WebTransport url ({host}:{port}): {e}").into())
}

#[async_trait]
impl LinkManagerUnicastTrait for LinkManagerUnicastWebTransport {
    async fn new_link(&self, endpoint: EndPoint) -> ZResult<LinkUnicast> {
        if let Some(name) = endpoint.metadata().get(handoff::HANDOFF) {
            // The session was dialled and authenticated by the application.
            let receiver = handoff::receiver(name);
            let mut receiver = receiver.lock().await;
            let handoff = tokio::time::timeout(Duration::from_secs(10), receiver.recv())
                .await
                .map_err(|_| zerror!("No WebTransport session was handed off to {endpoint}"))?
                .ok_or_else(|| zerror!("WebTransport handoff {name} was released"))?;
            return Ok(handoff::into_link(handoff));
        }
        let epaddr = endpoint.address();
        let epconf = endpoint.config();

        let dst_addr = get_quic_addr(&epaddr).await?;
        let host = get_quic_host(&epaddr)?;

        let client_crypto = TlsClientConfig::new(&epconf, true)
            .await
            .map_err(|e| zerror!("Cannot create a new WebTransport link to {endpoint}: {e}"))?;
        let mut rustls_config = client_crypto.client_config;
        rustls_config.alpn_protocols = vec![ALPN.as_bytes().to_vec()];

        let bind: IpAddr = if dst_addr.is_ipv4() {
            Ipv4Addr::UNSPECIFIED.into()
        } else {
            Ipv6Addr::UNSPECIFIED.into()
        };
        let mut quic_endpoint = quinn::Endpoint::client(SocketAddr::new(bind, 0))
            .map_err(|e| zerror!("Cannot create a new WebTransport link to {endpoint}: {e}"))?;
        let quic_client_config =
            quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
                .map_err(|e| zerror!("Cannot create a new WebTransport link to {endpoint}: {e}"))?;
        quic_endpoint
            .set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_client_config)));

        let src_addr = quic_endpoint
            .local_addr()
            .map_err(|e| zerror!("Cannot create a new WebTransport link to {endpoint}: {e}"))?;

        let conn = quic_endpoint
            .connect(dst_addr, host)
            .map_err(|e| zerror!("Cannot create a new WebTransport link to {endpoint}: {e}"))?
            .await
            .map_err(|e| zerror!("Cannot create a new WebTransport link to {endpoint}: {e}"))?;

        let url = connect_url(host, dst_addr.port())?;
        let session = Session::connect(conn, url)
            .await
            .map_err(|e| zerror!("WebTransport handshake failed for {endpoint}: {e}"))?;

        // The connecting side opens the single bidi stream carrying the zenoh session.
        let (send, recv) = session
            .open_bi()
            .await
            .map_err(|e| zerror!("WebTransport stream open failed for {endpoint}: {e}"))?;

        let link = Arc::new(LinkUnicastWebTransport::new(
            session, send, recv, src_addr, dst_addr,
        ));
        Ok(LinkUnicast::from(link as Arc<dyn LinkUnicastTrait>))
    }

    async fn new_listener(&self, mut endpoint: EndPoint) -> ZResult<Locator> {
        if let Some(name) = endpoint.metadata().get(handoff::HANDOFF).map(str::to_owned) {
            return self.new_handoff_listener(endpoint, name).await;
        }
        let epaddr = endpoint.address();
        let epconf = endpoint.config();

        let addr = get_quic_addr(&epaddr).await?;

        let server_crypto = TlsServerConfig::new(&epconf, true)
            .await
            .map_err(|e| zerror!("Cannot create a new WebTransport listener on {addr}: {e}"))?;
        let mut rustls_config = server_crypto.server_config;
        rustls_config.alpn_protocols = vec![ALPN.as_bytes().to_vec()];

        let quic_server_config =
            quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
                .map_err(|e| zerror!("Cannot create a new WebTransport listener on {addr}: {e}"))?;
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));

        let quic_endpoint = quinn::Endpoint::server(server_config, addr)
            .map_err(|e| zerror!("Cannot create a new WebTransport listener on {addr}: {e}"))?;
        let local_addr = quic_endpoint
            .local_addr()
            .map_err(|e| zerror!("Cannot create a new WebTransport listener on {addr}: {e}"))?;

        // Update the endpoint locator address
        endpoint = EndPoint::new(
            endpoint.protocol(),
            local_addr.to_string(),
            endpoint.metadata(),
            endpoint.config(),
        )?;

        let token = CancellationToken::new();
        let task = {
            let token = token.clone();
            let manager = self.manager.clone();
            let listeners = self.listeners.clone();

            async move {
                let res = accept_task(quic_endpoint, token, manager).await;
                zasyncwrite!(listeners).remove(&local_addr);
                res
            }
        };
        let handle = zenoh_runtime::ZRuntime::Acceptor.spawn(task);

        let locator = endpoint.to_locator();
        let listener = ListenerUnicastWebTransport {
            endpoint,
            token,
            handle,
        };
        zasyncwrite!(self.listeners).insert(local_addr, listener);

        Ok(locator)
    }

    async fn del_listener(&self, endpoint: &EndPoint) -> ZResult<()> {
        if let Some(name) = endpoint.metadata().get(handoff::HANDOFF) {
            let listener = zasyncwrite!(self.handoff_listeners)
                .remove(name)
                .ok_or_else(|| zerror!("WebTransport handoff listener {name} was not found"))?;
            listener.token.cancel();
            return listener.handle.await?;
        }
        let epaddr = endpoint.address();
        let addr = get_quic_addr(&epaddr).await?;

        let listener = zasyncwrite!(self.listeners).remove(&addr).ok_or_else(|| {
            zerror!("Cannot delete the WebTransport listener because it has not been found: {addr}")
        })?;

        listener.token.cancel();
        listener.handle.await?
    }

    async fn get_listeners(&self) -> Vec<EndPoint> {
        let mut endpoints: Vec<_> = zasyncread!(self.listeners)
            .values()
            .map(|l| l.endpoint.clone())
            .collect();
        endpoints.extend(
            zasyncread!(self.handoff_listeners)
                .values()
                .map(|l| l.endpoint.clone()),
        );
        endpoints
    }

    async fn get_locators(&self) -> Vec<Locator> {
        // A handoff queue is reachable only from inside this process, so it
        // is not a locator worth advertising to peers.
        zasyncread!(self.listeners)
            .values()
            .map(|l| l.endpoint.to_locator())
            .collect()
    }
}

impl LinkManagerUnicastWebTransport {
    async fn new_handoff_listener(&self, endpoint: EndPoint, name: String) -> ZResult<Locator> {
        let mut listeners = zasyncwrite!(self.handoff_listeners);
        if listeners.contains_key(&name) {
            return Err(zerror!("WebTransport handoff listener {name} already exists").into());
        }
        let token = CancellationToken::new();
        let receiver = handoff::receiver(&name);
        let task = {
            let token = token.clone();
            let manager = self.manager.clone();
            async move {
                let mut receiver = receiver.lock().await;
                loop {
                    tokio::select! {
                        handoff = receiver.recv() => {
                            let Some(handoff) = handoff else { break };
                            tracing::debug!("Accepted handed-off WebTransport session: {handoff:?}");
                            if let Err(e) = manager.send_async(handoff::into_link(handoff)).await {
                                tracing::error!("{}-{}: {}", file!(), line!(), e)
                            }
                        }
                        _ = token.cancelled() => break,
                    }
                }
                Ok(())
            }
        };
        let handle = zenoh_runtime::ZRuntime::Acceptor.spawn(task);
        let locator = endpoint.to_locator();
        listeners.insert(
            name,
            ListenerUnicastWebTransport {
                endpoint,
                token,
                handle,
            },
        );
        Ok(locator)
    }
}

async fn accept_task(
    quic_endpoint: quinn::Endpoint,
    token: CancellationToken,
    manager: NewLinkChannelSender,
) -> ZResult<()> {
    let src_addr = quic_endpoint
        .local_addr()
        .map_err(|e| zerror!("Cannot accept WebTransport connections: {e}"))?;

    tracing::trace!("Ready to accept WebTransport connections on: {src_addr:?}");
    loop {
        tokio::select! {
            incoming = quic_endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let manager = manager.clone();
                // Handshake each connection in its own task so a slow peer
                // cannot stall the accept loop.
                zenoh_runtime::ZRuntime::Acceptor.spawn(async move {
                    match tokio::time::timeout(
                        Duration::from_secs(10),
                        webtransport_handshake(incoming, src_addr),
                    )
                    .await
                    {
                        Ok(Ok(link)) => {
                            if let Err(e) = manager.send_async(link).await {
                                tracing::error!("{}-{}: {}", file!(), line!(), e)
                            }
                        }
                        Ok(Err(e)) => tracing::debug!("WebTransport handshake failed: {e}"),
                        Err(_) => tracing::debug!("WebTransport handshake timed out"),
                    }
                });
            }
            _ = token.cancelled() => break,
        }
    }
    Ok(())
}

async fn webtransport_handshake(
    incoming: quinn::Incoming,
    src_addr: SocketAddr,
) -> ZResult<LinkUnicast> {
    let conn = incoming
        .await
        .map_err(|e| zerror!("QUIC accept failed on {src_addr}: {e}"))?;
    let dst_addr = conn.remote_address();

    // H3 SETTINGS + Extended CONNECT (any path is accepted).
    let request = Request::accept(conn)
        .await
        .map_err(|e| zerror!("WebTransport CONNECT failed from {dst_addr}: {e}"))?;
    let session = request
        .ok()
        .await
        .map_err(|e| zerror!("WebTransport session setup failed from {dst_addr}: {e}"))?;

    // The connecting side opens the bidi stream; it resolves when the first
    // bytes of the zenoh handshake arrive.
    let (send, recv) = session
        .accept_bi()
        .await
        .map_err(|e| zerror!("WebTransport stream accept failed from {dst_addr}: {e}"))?;

    tracing::debug!("Accepted WebTransport connection on {src_addr:?}: {dst_addr:?}");
    let link = Arc::new(LinkUnicastWebTransport::new(
        session, send, recv, src_addr, dst_addr,
    ));
    Ok(LinkUnicast::from(link as Arc<dyn LinkUnicastTrait>))
}
