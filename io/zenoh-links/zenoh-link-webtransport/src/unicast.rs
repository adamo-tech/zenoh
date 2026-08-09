//
// Copyright (c) 2026 Adamo Technology Ltd.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//

use std::{
    collections::HashMap,
    fmt,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::{Arc, LazyLock, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tokio::sync::{Mutex as AsyncMutex, RwLock as AsyncRwLock};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use wtransport::{
    endpoint::{endpoint_side, IncomingSession},
    tls::Identity,
    ClientConfig, Connection, Endpoint, ServerConfig, VarInt,
};
use zenoh_core::{zasynclock, zasyncread, zasyncwrite};
use zenoh_link_commons::{
    get_ip_interface_names,
    tls::config::{TLS_LISTEN_CERTIFICATE_FILE, TLS_LISTEN_PRIVATE_KEY_FILE},
    LinkAuthId, LinkKeyExprPermission, LinkManagerUnicastTrait, LinkUnicast, LinkUnicastTrait,
    NewLinkChannelSender,
};
use zenoh_protocol::{
    core::{EndPoint, Locator, Priority},
    transport::BatchSize,
};
use zenoh_result::{bail, zerror, ZResult};

use super::{
    WEBTRANSPORT_DEFAULT_MTU, WEBTRANSPORT_DEFAULT_PATH, WEBTRANSPORT_LOCATOR_PREFIX,
    WEBTRANSPORT_PATH_CONFIG,
    WEBTRANSPORT_JWT_AUDIENCE_CONFIG, WEBTRANSPORT_JWT_PUBLIC_KEY_FILE_CONFIG,
    WEBTRANSPORT_SERVER_CERTIFICATE_HASH_CONFIG,
};

static PREBOUND_SERVER_SOCKETS: LazyLock<Mutex<HashMap<SocketAddr, std::net::UdpSocket>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Register a UDP socket for the next WebTransport listener created on its
/// local address. This lets reachability/STUN code warm the exact socket that
/// the Zenoh link subsequently owns, preserving the advertised NAT mapping.
pub fn register_prebound_server_socket(socket: std::net::UdpSocket) -> ZResult<SocketAddr> {
    socket.set_nonblocking(true).map_err(|error| {
        zerror!("Can not make pre-bound WebTransport socket nonblocking: {error}")
    })?;
    let address = socket.local_addr().map_err(|error| {
        zerror!("Can not inspect pre-bound WebTransport socket: {error}")
    })?;
    let mut sockets = PREBOUND_SERVER_SOCKETS
        .lock()
        .map_err(|_| zerror!("Pre-bound WebTransport socket registry is poisoned"))?;
    if sockets.insert(address, socket).is_some() {
        bail!("A pre-bound WebTransport socket is already registered for {address}");
    }
    Ok(address)
}

/// Remove a registered socket when session setup fails before the listener can
/// take ownership of it. Returns true when a socket was still pending.
pub fn unregister_prebound_server_socket(address: SocketAddr) -> bool {
    PREBOUND_SERVER_SOCKETS
        .lock()
        .map(|mut sockets| sockets.remove(&address).is_some())
        .unwrap_or(false)
}

fn take_prebound_server_socket(address: SocketAddr) -> ZResult<Option<std::net::UdpSocket>> {
    Ok(PREBOUND_SERVER_SOCKETS
        .lock()
        .map_err(|_| zerror!("Pre-bound WebTransport socket registry is poisoned"))?
        .remove(&address))
}

#[derive(Debug, Deserialize)]
struct WebTransportJwtClaims {
    sub: String,
    scope: String,
}

struct WebTransportJwtVerifier {
    key: DecodingKey,
    validation: Validation,
}

impl WebTransportJwtVerifier {
    async fn from_endpoint(endpoint: &EndPoint) -> ZResult<Option<Self>> {
        let key_file = endpoint.config().get(WEBTRANSPORT_JWT_PUBLIC_KEY_FILE_CONFIG);
        let audience = endpoint.config().get(WEBTRANSPORT_JWT_AUDIENCE_CONFIG);
        match (key_file, audience) {
            (None, None) => Ok(None),
            (Some(_), None) | (None, Some(_)) => bail!(
                "WebTransport listener JWT auth requires both '{}' and '{}'",
                WEBTRANSPORT_JWT_PUBLIC_KEY_FILE_CONFIG,
                WEBTRANSPORT_JWT_AUDIENCE_CONFIG
            ),
            (Some(key_file), Some(audience)) => {
                let pem = tokio::fs::read(key_file).await.map_err(|e| {
                    zerror!("Can not read WebTransport JWT public key '{}': {}", key_file, e)
                })?;
                let key = DecodingKey::from_ec_pem(&pem).map_err(|e| {
                    zerror!("Can not parse WebTransport JWT EC public key '{}': {}", key_file, e)
                })?;
                let mut validation = Validation::new(Algorithm::ES256);
                validation.set_audience(&[audience]);
                validation.set_required_spec_claims(&["exp", "sub", "aud"]);
                Ok(Some(Self { key, validation }))
            }
        }
    }

    fn authorize(&self, request_path: &str) -> ZResult<(String, Vec<LinkKeyExprPermission>)> {
        let token = request_path
            .split_once('?')
            .map(|(_, query)| query)
            .and_then(|query| {
                url::form_urlencoded::parse(query.as_bytes())
                    .find_map(|(key, value)| (key == "token").then(|| value.into_owned()))
            })
            .ok_or_else(|| zerror!("WebTransport request is missing its bearer token"))?;
        let claims = jsonwebtoken::decode::<WebTransportJwtClaims>(&token, &self.key, &self.validation)
            .map_err(|e| zerror!("WebTransport bearer token is invalid: {}", e))?
            .claims;
        let permissions = claims
            .scope
            .split_ascii_whitespace()
            .map(|scope| {
                let value = scope.strip_prefix("zenoh:").ok_or_else(|| {
                    zerror!("WebTransport bearer token contains unsupported scope '{}'", scope)
                })?;
                let (action, keyexpr) = value.split_once(':').ok_or_else(|| {
                    zerror!("WebTransport bearer token contains malformed Zenoh scope '{}'", scope)
                })?;
                if !matches!(
                    action,
                    "*"
                        | "put"
                        | "delete"
                        | "declare_subscriber"
                        | "query"
                        | "declare_queryable"
                        | "reply"
                        | "liveliness_token"
                        | "declare_liveliness_subscriber"
                        | "liveliness_query"
                ) {
                    bail!("WebTransport bearer token contains unknown Zenoh action '{}'", action);
                }
                zenoh_keyexpr::keyexpr::new(keyexpr).map_err(|e| {
                    zerror!(
                        "WebTransport bearer token contains invalid key-expression '{}': {}",
                        keyexpr,
                        e
                    )
                })?;
                Ok(LinkKeyExprPermission {
                    action: action.to_owned(),
                    keyexpr: keyexpr.to_owned(),
                })
            })
            .collect::<ZResult<Vec<_>>>()?;
        if claims.sub.is_empty() || permissions.is_empty() {
            bail!("WebTransport bearer token has no subject or Zenoh permissions");
        }
        Ok((claims.sub, permissions))
    }
}

pub struct LinkUnicastWebTransport {
    // A wtransport client connection is owned by its endpoint. Keep the
    // endpoint alive for exactly as long as the Zenoh link.
    _client_endpoint: Option<Endpoint<endpoint_side::Client>>,
    connection: Connection,
    send: AsyncMutex<wtransport::stream::SendStream>,
    recv: AsyncMutex<wtransport::stream::RecvStream>,
    src_addr: SocketAddr,
    src_locator: Locator,
    dst_addr: SocketAddr,
    dst_locator: Locator,
    auth_id: LinkAuthId,
    authenticated_permissions: Vec<LinkKeyExprPermission>,
}

impl LinkUnicastWebTransport {
    fn new(
        client_endpoint: Option<Endpoint<endpoint_side::Client>>,
        connection: Connection,
        send: wtransport::stream::SendStream,
        recv: wtransport::stream::RecvStream,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        auth_id: LinkAuthId,
        authenticated_permissions: Vec<LinkKeyExprPermission>,
    ) -> Self {
        Self {
            _client_endpoint: client_endpoint,
            connection,
            send: AsyncMutex::new(send),
            recv: AsyncMutex::new(recv),
            src_addr,
            src_locator: Locator::new(
                WEBTRANSPORT_LOCATOR_PREFIX,
                src_addr.to_string(),
                "",
            )
            .unwrap(),
            dst_addr,
            dst_locator: Locator::new(
                WEBTRANSPORT_LOCATOR_PREFIX,
                dst_addr.to_string(),
                "",
            )
            .unwrap(),
            auth_id,
            authenticated_permissions,
        }
    }
}

#[async_trait]
impl LinkUnicastTrait for LinkUnicastWebTransport {
    async fn close(&self) -> ZResult<()> {
        tracing::trace!("Closing WebTransport link: {}", self);
        self.connection
            .close(VarInt::from_u32(0), b"zenoh link closed");
        Ok(())
    }

    async fn write(&self, buffer: &[u8], _priority: Option<Priority>) -> ZResult<usize> {
        zasynclock!(self.send).write(buffer).await.map_err(|e| {
            zerror!("Write error on WebTransport link {}: {}", self, e).into()
        })
    }

    async fn write_all(&self, buffer: &[u8], _priority: Option<Priority>) -> ZResult<()> {
        zasynclock!(self.send)
            .write_all(buffer)
            .await
            .map_err(|e| {
                zerror!("Write error on WebTransport link {}: {}", self, e).into()
            })
    }

    async fn read(&self, buffer: &mut [u8], _priority: Option<Priority>) -> ZResult<usize> {
        match zasynclock!(self.recv).read(buffer).await {
            Ok(Some(read)) => Ok(read),
            Ok(None) => bail!("WebTransport link {} closed while reading", self),
            Err(e) => bail!("Read error on WebTransport link {}: {}", self, e),
        }
    }

    async fn read_exact(&self, buffer: &mut [u8], priority: Option<Priority>) -> ZResult<()> {
        let mut offset = 0;
        while offset < buffer.len() {
            offset += self.read(&mut buffer[offset..], priority).await?;
        }
        Ok(())
    }

    fn get_mtu(&self) -> BatchSize {
        *WEBTRANSPORT_DEFAULT_MTU
    }

    fn get_src(&self) -> &Locator {
        &self.src_locator
    }

    fn get_dst(&self) -> &Locator {
        &self.dst_locator
    }

    fn is_reliable(&self) -> bool {
        true
    }

    fn is_streamed(&self) -> bool {
        true
    }

    fn get_interface_names(&self) -> Vec<String> {
        get_ip_interface_names(&self.src_addr)
    }

    fn get_auth_id(&self) -> &LinkAuthId {
        &self.auth_id
    }

    fn get_authenticated_permissions(&self) -> &[LinkKeyExprPermission] {
        &self.authenticated_permissions
    }
}

impl Drop for LinkUnicastWebTransport {
    fn drop(&mut self) {
        self.connection
            .close(VarInt::from_u32(0), b"zenoh link dropped");
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

struct ListenerUnicastWebTransport {
    endpoint: EndPoint,
    token: CancellationToken,
    handle: JoinHandle<ZResult<()>>,
}

impl ListenerUnicastWebTransport {
    async fn stop(&self) {
        self.token.cancel();
    }
}

pub struct LinkManagerUnicastWebTransport {
    manager: NewLinkChannelSender,
    listeners: Arc<AsyncRwLock<HashMap<SocketAddr, ListenerUnicastWebTransport>>>,
}

impl LinkManagerUnicastWebTransport {
    pub fn new(manager: NewLinkChannelSender) -> Self {
        Self {
            manager,
            listeners: Arc::new(AsyncRwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl LinkManagerUnicastTrait for LinkManagerUnicastWebTransport {
    async fn new_link(&self, endpoint: EndPoint) -> ZResult<LinkUnicast> {
        let path = endpoint_path(&endpoint)?;
        let url = format!("https://{}{}", endpoint.address().as_str(), path);
        let client_config = if let Some(hash) = endpoint
            .config()
            .get(WEBTRANSPORT_SERVER_CERTIFICATE_HASH_CONFIG)
        {
            let digest = wtransport::tls::Sha256Digest::from_str(hash).map_err(|e| {
                zerror!(
                    "Invalid WebTransport server certificate hash for {}: {}",
                    endpoint,
                    e
                )
            })?;
            ClientConfig::builder()
                .with_bind_default()
                .with_server_certificate_hashes([digest])
                .build()
        } else {
            ClientConfig::builder()
                .with_bind_default()
                .with_native_certs()
                .build()
        };

        let client = Endpoint::client(client_config)
            .map_err(|e| zerror!("Can not create WebTransport client endpoint: {}", e))?;
        let src_addr = client
            .local_addr()
            .map_err(|e| zerror!("Can not inspect WebTransport client endpoint: {}", e))?;
        let connection = client.connect(&url).await.map_err(|e| {
            zerror!("Can not connect WebTransport link to {}: {}", url, e)
        })?;
        let dst_addr = connection.remote_address();
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| zerror!("Can not open Zenoh WebTransport stream: {}", e))?
            .await
            .map_err(|e| zerror!("Can not initialize Zenoh WebTransport stream: {}", e))?;

        let link: Arc<dyn LinkUnicastTrait> = Arc::new(LinkUnicastWebTransport::new(
            Some(client),
            connection,
            send,
            recv,
            src_addr,
            dst_addr,
            LinkAuthId::WebTransport(None),
            Vec::new(),
        ));
        Ok(LinkUnicast::from(link))
    }

    async fn new_listener(&self, mut endpoint: EndPoint) -> ZResult<Locator> {
        let addr = resolve_addr(&endpoint).await?;
        let cert_file = endpoint
            .config()
            .get(TLS_LISTEN_CERTIFICATE_FILE)
            .ok_or_else(|| {
                zerror!(
                    "WebTransport listener {} requires '{}'",
                    endpoint,
                    TLS_LISTEN_CERTIFICATE_FILE
                )
            })?;
        let key_file = endpoint
            .config()
            .get(TLS_LISTEN_PRIVATE_KEY_FILE)
            .ok_or_else(|| {
                zerror!(
                    "WebTransport listener {} requires '{}'",
                    endpoint,
                    TLS_LISTEN_PRIVATE_KEY_FILE
                )
            })?;
        let path = endpoint_path(&endpoint)?.to_owned();
        let jwt_verifier = WebTransportJwtVerifier::from_endpoint(&endpoint)
            .await?
            .map(Arc::new);
        let identity = Identity::load_pemfiles(cert_file, key_file)
            .await
            .map_err(|e| zerror!("Can not load WebTransport listener identity: {}", e))?;
        let config_builder = ServerConfig::builder();
        let config_builder = match take_prebound_server_socket(addr)? {
            Some(socket) => config_builder.with_bind_socket(socket),
            None => config_builder.with_bind_address(addr),
        };
        let config = config_builder
            .with_identity(identity)
            .keep_alive_interval(Some(Duration::from_secs(3)))
            .build();
        let server = Endpoint::server(config).map_err(|e| {
            zerror!("Can not create WebTransport listener on {}: {}", addr, e)
        })?;
        let local_addr = server
            .local_addr()
            .map_err(|e| zerror!("Can not inspect WebTransport listener: {}", e))?;

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
                let result = accept_task(server, local_addr, path, jwt_verifier, token, manager).await;
                zasyncwrite!(listeners).remove(&local_addr);
                result
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
        let addr = resolve_addr(endpoint).await?;
        let listener = zasyncwrite!(self.listeners).remove(&addr).ok_or_else(|| {
            zerror!(
                "Can not delete WebTransport listener because it was not found: {}",
                addr
            )
        })?;
        listener.stop().await;
        listener.handle.await?
    }

    async fn get_listeners(&self) -> Vec<EndPoint> {
        zasyncread!(self.listeners)
            .values()
            .map(|listener| listener.endpoint.clone())
            .collect()
    }

    async fn get_locators(&self) -> Vec<Locator> {
        let mut locators = Vec::new();
        let guard = zasyncread!(self.listeners);
        for (address, listener) in guard.iter() {
            if address.ip() == Ipv4Addr::UNSPECIFIED || address.ip() == Ipv6Addr::UNSPECIFIED {
                if let Ok(local_addresses) = zenoh_util::net::get_local_addresses(None) {
                    for ip in local_addresses.into_iter().filter(|ip| {
                        !ip.is_loopback()
                            && !ip.is_multicast()
                            && ip.is_ipv4() == address.is_ipv4()
                    }) {
                        if let Ok(locator) = Locator::new(
                            WEBTRANSPORT_LOCATOR_PREFIX,
                            SocketAddr::new(ip, address.port()).to_string(),
                            listener.endpoint.metadata(),
                        ) {
                            locators.push(locator);
                        }
                    }
                }
            } else {
                locators.push(listener.endpoint.to_locator());
            }
        }
        locators
    }
}

async fn accept_task(
    server: Endpoint<wtransport::endpoint::endpoint_side::Server>,
    local_addr: SocketAddr,
    path: String,
    jwt_verifier: Option<Arc<WebTransportJwtVerifier>>,
    token: CancellationToken,
    manager: NewLinkChannelSender,
) -> ZResult<()> {
    tracing::trace!("Ready to accept WebTransport connections on {}", local_addr);
    loop {
        let incoming = tokio::select! {
            incoming = server.accept() => incoming,
            _ = token.cancelled() => {
                break;
            }
        };
        let manager = manager.clone();
        let path = path.clone();
        let jwt_verifier = jwt_verifier.clone();
        zenoh_runtime::ZRuntime::Acceptor.spawn(async move {
            if let Err(e) = accept_one(incoming, local_addr, &path, jwt_verifier.as_deref(), manager).await {
                tracing::warn!("WebTransport connection was not accepted: {}", e);
            }
        });
    }
    Ok(())
}

async fn accept_one(
    incoming: IncomingSession,
    local_addr: SocketAddr,
    path: &str,
    jwt_verifier: Option<&WebTransportJwtVerifier>,
    manager: NewLinkChannelSender,
) -> ZResult<()> {
    let request = incoming
        .await
        .map_err(|e| zerror!("WebTransport session request failed: {}", e))?;
    let request_path = request
        .path()
        .split('?')
        .next()
        .unwrap_or(request.path())
        .to_owned();
    if request_path != path {
        request.not_found().await;
        bail!(
            "WebTransport request used path '{}', expected '{}'",
            request_path,
            path
        );
    }
    let (auth_id, authenticated_permissions) = if let Some(verifier) = jwt_verifier {
        match verifier.authorize(request.path()) {
            Ok((subject, scopes)) => (LinkAuthId::WebTransport(Some(subject)), scopes),
            Err(error) => {
                request.forbidden().await;
                return Err(error);
            }
        }
    } else {
        (LinkAuthId::WebTransport(None), Vec::new())
    };
    let dst_addr = request.remote_address();
    let connection = request
        .accept()
        .await
        .map_err(|e| zerror!("WebTransport session acceptance failed: {}", e))?;
    let (send, recv) = connection.accept_bi().await.map_err(|e| {
        zerror!(
            "WebTransport peer {} did not open a Zenoh bidirectional stream: {}",
            dst_addr,
            e
        )
    })?;
    let link: Arc<dyn LinkUnicastTrait> = Arc::new(LinkUnicastWebTransport::new(
        None,
        connection,
        send,
        recv,
        local_addr,
        dst_addr,
        auth_id,
        authenticated_permissions,
    ));
    manager
        .send_async(LinkUnicast::from(link))
        .await
        .map_err(|e| zerror!("Can not deliver accepted WebTransport link: {}", e))?;
    Ok(())
}

fn endpoint_path(endpoint: &EndPoint) -> ZResult<&str> {
    let path = endpoint
        .config()
        .get(WEBTRANSPORT_PATH_CONFIG)
        .unwrap_or(WEBTRANSPORT_DEFAULT_PATH);
    if !path.starts_with('/') || path.contains('?') || path.contains('#') {
        bail!(
            "Invalid WebTransport path '{}': expected an absolute path without query or fragment",
            path
        );
    }
    Ok(path)
}

async fn resolve_addr(endpoint: &EndPoint) -> ZResult<SocketAddr> {
    Ok(tokio::net::lookup_host(endpoint.address().as_str())
        .await?
        .next()
        .ok_or_else(|| {
            zerror!(
                "Could not resolve WebTransport locator address {}",
                endpoint.address()
            )
        })?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use rcgen::KeyPair;
    use serde::Serialize;
    use wtransport::tls::Sha256DigestFmt;

    #[derive(Serialize)]
    struct TestClaims {
        sub: &'static str,
        scope: &'static str,
        aud: &'static str,
        exp: usize,
    }

    #[test]
    fn jwt_authorization_extracts_validated_zenoh_permissions() {
        let pair = KeyPair::generate().unwrap();
        let key = EncodingKey::from_ec_pem(pair.serialize_pem().as_bytes()).unwrap();
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&["zenoh-webtransport"]);
        validation.set_required_spec_claims(&["exp", "sub", "aud"]);
        let verifier = WebTransportJwtVerifier {
            key: DecodingKey::from_ec_pem(pair.public_key_pem().as_bytes()).unwrap(),
            validation,
        };
        let token = encode(
            &Header::new(Algorithm::ES256),
            &TestClaims {
                sub: "operator-1",
                scope: "zenoh:*:adamo/example/** zenoh:put:adamo/_time/ping/*",
                aud: "zenoh-webtransport",
                exp: 9_999_999_999,
            },
            &key,
        )
        .unwrap();

        let (subject, permissions) = verifier
            .authorize(&format!("/zenoh?token={token}"))
            .unwrap();
        assert_eq!(subject, "operator-1");
        assert_eq!(permissions[0].action, "*");
        assert_eq!(permissions[0].keyexpr, "adamo/example/**");
        assert_eq!(permissions[1].action, "put");
        assert_eq!(permissions[1].keyexpr, "adamo/_time/ping/*");
        assert!(verifier.authorize("/zenoh").is_err());
        assert!(verifier.authorize("/zenoh?token=not-a-jwt").is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn listener_authenticates_before_delivering_the_link() {
        let identity = Identity::self_signed(["localhost", "127.0.0.1"]).unwrap();
        let digest = identity.certificate_chain().as_slice()[0].hash();
        let jwt_pair = KeyPair::generate().unwrap();
        let jwt_key = EncodingKey::from_ec_pem(jwt_pair.serialize_pem().as_bytes()).unwrap();
        let token = encode(
            &Header::new(Algorithm::ES256),
            &TestClaims {
                sub: "operator-1",
                scope: "zenoh:*:adamo/example/** zenoh:put:adamo/_time/ping/*",
                aud: "p2p",
                exp: 9_999_999_999,
            },
            &jwt_key,
        )
        .unwrap();
        let test_dir = std::env::temp_dir().join(format!(
            "zenoh-webtransport-auth-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&test_dir).unwrap();
        let cert_file = test_dir.join("certificate.pem");
        let key_file = test_dir.join("private-key.pem");
        let jwt_file = test_dir.join("jwt-public.pem");
        identity
            .certificate_chain()
            .store_pemfile(&cert_file)
            .await
            .unwrap();
        identity
            .private_key()
            .store_secret_pemfile(&key_file)
            .await
            .unwrap();
        std::fs::write(&jwt_file, jwt_pair.public_key_pem()).unwrap();

        let (accepted_tx, accepted_rx) = flume::bounded(1);
        let listener_manager = LinkManagerUnicastWebTransport::new(accepted_tx);
        let listen_config = format!(
            "{}={};{}={};{}={};{}=p2p",
            TLS_LISTEN_CERTIFICATE_FILE,
            cert_file.display(),
            TLS_LISTEN_PRIVATE_KEY_FILE,
            key_file.display(),
            WEBTRANSPORT_JWT_PUBLIC_KEY_FILE_CONFIG,
            jwt_file.display(),
            WEBTRANSPORT_JWT_AUDIENCE_CONFIG,
        );
        let listen_endpoint = EndPoint::new(
            WEBTRANSPORT_LOCATOR_PREFIX,
            "127.0.0.1:0",
            "",
            listen_config.clone(),
        )
        .unwrap();
        let locator = listener_manager.new_listener(listen_endpoint).await.unwrap();
        let client = Endpoint::client(
            ClientConfig::builder()
                .with_bind_default()
                .with_server_certificate_hashes([digest])
                .build(),
        )
        .unwrap();
        let connection = client
            .connect(&format!("https://{}/zenoh?token={token}", locator.address()))
            .await
            .unwrap();
        let _stream = connection.open_bi().await.unwrap().await.unwrap();
        let accepted = accepted_rx.recv_async().await.unwrap();
        assert_eq!(
            accepted.get_auth_id(),
            &LinkAuthId::WebTransport(Some("operator-1".into()))
        );
        assert_eq!(accepted.get_authenticated_permissions().len(), 2);
        assert_eq!(accepted.get_authenticated_permissions()[1].action, "put");

        let actual_listener = EndPoint::new(
            WEBTRANSPORT_LOCATOR_PREFIX,
            locator.address(),
            "",
            listen_config,
        )
        .unwrap();
        listener_manager.del_listener(&actual_listener).await.unwrap();
        std::fs::remove_file(cert_file).unwrap();
        std::fs::remove_file(key_file).unwrap();
        std::fs::remove_file(jwt_file).unwrap();
        std::fs::remove_dir(test_dir).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn listener_takes_ownership_of_the_prebound_socket() {
        let identity = Identity::self_signed(["localhost", "127.0.0.1"]).unwrap();
        let test_dir = std::env::temp_dir().join(format!(
            "zenoh-webtransport-prebound-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&test_dir).unwrap();
        let cert_file = test_dir.join("certificate.pem");
        let key_file = test_dir.join("private-key.pem");
        identity
            .certificate_chain()
            .store_pemfile(&cert_file)
            .await
            .unwrap();
        identity
            .private_key()
            .store_secret_pemfile(&key_file)
            .await
            .unwrap();

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = register_prebound_server_socket(socket).unwrap();
        let (accepted_tx, _accepted_rx) = flume::bounded(1);
        let listener_manager = LinkManagerUnicastWebTransport::new(accepted_tx);
        let listen_config = format!(
            "{}={};{}={}",
            TLS_LISTEN_CERTIFICATE_FILE,
            cert_file.display(),
            TLS_LISTEN_PRIVATE_KEY_FILE,
            key_file.display()
        );
        let endpoint = EndPoint::new(
            WEBTRANSPORT_LOCATOR_PREFIX,
            address.to_string(),
            "",
            listen_config.clone(),
        )
        .unwrap();
        let locator = listener_manager.new_listener(endpoint).await.unwrap();

        assert_eq!(locator.address().as_str(), address.to_string());
        assert!(!unregister_prebound_server_socket(address));

        let actual_listener = EndPoint::new(
            WEBTRANSPORT_LOCATOR_PREFIX,
            locator.address(),
            "",
            listen_config,
        )
        .unwrap();
        listener_manager.del_listener(&actual_listener).await.unwrap();
        std::fs::remove_file(cert_file).unwrap();
        std::fs::remove_file(key_file).unwrap();
        std::fs::remove_dir(test_dir).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reliable_stream_round_trip() {
        let identity = Identity::self_signed(["localhost", "127.0.0.1"]).unwrap();
        let hash = identity.certificate_chain().as_slice()[0]
            .hash()
            .fmt(Sha256DigestFmt::DottedHex);
        let test_dir = std::env::temp_dir().join(format!(
            "zenoh-webtransport-link-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&test_dir).unwrap();
        let cert_file = test_dir.join("certificate.pem");
        let key_file = test_dir.join("private-key.pem");
        identity
            .certificate_chain()
            .store_pemfile(&cert_file)
            .await
            .unwrap();
        identity
            .private_key()
            .store_secret_pemfile(&key_file)
            .await
            .unwrap();

        let (accepted_tx, accepted_rx) = flume::bounded(1);
        let listener_manager = LinkManagerUnicastWebTransport::new(accepted_tx);
        let listen_config = format!(
            "{}={};{}={}",
            TLS_LISTEN_CERTIFICATE_FILE,
            cert_file.display(),
            TLS_LISTEN_PRIVATE_KEY_FILE,
            key_file.display()
        );
        let listen_endpoint = EndPoint::new(
            WEBTRANSPORT_LOCATOR_PREFIX,
            "127.0.0.1:0",
            "",
            listen_config.clone(),
        )
        .unwrap();
        let locator = listener_manager
            .new_listener(listen_endpoint)
            .await
            .unwrap();

        let (unused_tx, _unused_rx) = flume::bounded(1);
        let client_manager = LinkManagerUnicastWebTransport::new(unused_tx);
        let client_endpoint = EndPoint::new(
            WEBTRANSPORT_LOCATOR_PREFIX,
            locator.address(),
            "",
            format!(
                "{}={}",
                WEBTRANSPORT_SERVER_CERTIFICATE_HASH_CONFIG, hash
            ),
        )
        .unwrap();
        let client = client_manager.new_link(client_endpoint).await.unwrap();
        let server = accepted_rx.recv_async().await.unwrap();

        client.write_all(b"standard zenoh bytes", None).await.unwrap();
        let mut received = [0; 20];
        server.read_exact(&mut received, None).await.unwrap();
        assert_eq!(&received, b"standard zenoh bytes");

        server.write_all(b"reply", None).await.unwrap();
        let mut reply = [0; 5];
        client.read_exact(&mut reply, None).await.unwrap();
        assert_eq!(&reply, b"reply");

        let actual_listener = EndPoint::new(
            WEBTRANSPORT_LOCATOR_PREFIX,
            locator.address(),
            "",
            listen_config,
        )
        .unwrap();
        listener_manager
            .del_listener(&actual_listener)
            .await
            .unwrap();
        std::fs::remove_file(cert_file).unwrap();
        std::fs::remove_file(key_file).unwrap();
        std::fs::remove_dir(test_dir).unwrap();
    }
}
