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

//! In-process handoff of WebTransport sessions authenticated outside Zenoh.
//!
//! An application that terminates WebTransport itself, for example to serve
//! signalling, STUN and pairing on one socket, passes each session here
//! instead of copying its bytes through another link. Zenoh then owns the
//! real QUIC connection: it reports that connection's stats and, when the
//! application negotiated it, carries best-effort batches as datagrams on a
//! companion link.
//!
//! A listener endpoint `webtransport/<name>?handoff=<name>` accepts every
//! session handed to `<name>`; a connect endpoint of the same form takes one.

#[cfg(all(feature = "uring", target_os = "linux"))]
use std::os::fd::RawFd;
use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, LazyLock, Mutex},
};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use web_transport_quinn::{RecvStream, SendStream, Session};
use zenoh_link_commons::{
    get_ip_interface_names, quic::unicast::QuicConnection, LinkAuthId, LinkUnicast,
    LinkUnicastTrait, NewLink,
};
use zenoh_protocol::{
    core::{Locator, Priority},
    transport::BatchSize,
};
#[cfg(all(feature = "uring", target_os = "linux"))]
use zenoh_result::bail;
use zenoh_result::{zerror, ZResult};

use super::{LinkUnicastWebTransport, WEBTRANSPORT_LOCATOR_PREFIX};

/// Endpoint metadata key naming the handoff queue.
pub const HANDOFF: &str = "handoff";

/// The largest best-effort batch a handed-off session carries in one
/// datagram. 1200 bytes leaves room for tunnels and avoids IP fragmentation;
/// browsers apply the same ceiling to what they send.
pub const MAX_DATAGRAM_BATCH: usize = 1200;

/// Sessions that may wait for a listener before new ones are refused.
const QUEUE: usize = 32;

/// One WebTransport session ready to carry a Zenoh transport.
pub struct Handoff {
    pub session: Session,
    /// The bidirectional stream carrying the reliable, length-prefixed batches.
    pub send: SendStream,
    pub recv: RecvStream,
    /// The session's QUIC connection, built with
    /// [`zenoh_link_commons::quic::unicast::track_delivery`].
    pub connection: QuicConnection,
    /// Both peers agreed to carry best-effort batches as datagrams.
    pub mixed_reliability: bool,
}

impl fmt::Debug for Handoff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Handoff")
            .field("remote", &self.session.remote_address())
            .field("mixed_reliability", &self.mixed_reliability)
            .finish()
    }
}

/// The datagram payload, in bytes, a handed-off session can carry: the
/// session's own limit capped at [`MAX_DATAGRAM_BATCH`]. Zero when the peer
/// does not accept datagrams.
pub fn datagram_mtu(session: &Session) -> u16 {
    session.max_datagram_size().min(MAX_DATAGRAM_BATCH) as u16
}

type Queue = (
    mpsc::Sender<Handoff>,
    Arc<AsyncMutex<mpsc::Receiver<Handoff>>>,
);

static QUEUES: LazyLock<Mutex<HashMap<String, Queue>>> = LazyLock::new(Default::default);

fn queue(name: &str) -> Queue {
    let mut queues = QUEUES.lock().unwrap_or_else(|e| e.into_inner());
    queues
        .entry(name.to_owned())
        .or_insert_with(|| {
            let (tx, rx) = mpsc::channel(QUEUE);
            (tx, Arc::new(AsyncMutex::new(rx)))
        })
        .clone()
}

/// Queue `handoff` for the endpoint named `name`. Fails, closing nothing,
/// when that many sessions are already waiting.
pub fn hand_off(name: &str, handoff: Handoff) -> ZResult<()> {
    queue(name).0.try_send(handoff).map_err(|e| {
        let handoff = match e {
            mpsc::error::TrySendError::Full(h) | mpsc::error::TrySendError::Closed(h) => h,
        };
        handoff.session.close(0, b"handoff queue full");
        zerror!("WebTransport handoff queue {name} is full").into()
    })
}

/// Forget the queue named `name`, dropping any session still waiting in it.
pub fn release(name: &str) {
    QUEUES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(name);
}

pub(crate) fn receiver(name: &str) -> Arc<AsyncMutex<mpsc::Receiver<Handoff>>> {
    queue(name).1
}

pub(crate) fn into_link(handoff: Handoff) -> LinkUnicast {
    let Handoff {
        session,
        send,
        recv,
        connection,
        mixed_reliability,
    } = handoff;
    let src_addr = SocketAddr::new(
        connection
            .local_ip()
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        0,
    );
    let dst_addr = connection.remote_address();
    let mtu = datagram_mtu(&session);
    let mixed_reliability = mixed_reliability && mtu > 0;
    let reliable = Arc::new(LinkUnicastWebTransport::tracked(
        session.clone(),
        send,
        recv,
        src_addr,
        dst_addr,
        connection.clone(),
        mixed_reliability,
    ));
    if !mixed_reliability {
        return LinkUnicast::from(reliable as Arc<dyn LinkUnicastTrait>);
    }
    let best_effort = Arc::new(LinkUnicastWebTransportDatagram {
        src_locator: Locator::new(WEBTRANSPORT_LOCATOR_PREFIX, src_addr.to_string(), "rel=0")
            .unwrap(),
        dst_locator: Locator::new(WEBTRANSPORT_LOCATOR_PREFIX, dst_addr.to_string(), "rel=0")
            .unwrap(),
        session,
        connection,
        src_addr,
        mtu,
        auth_id: LinkAuthId::WebTransport,
    });
    LinkUnicast(NewLink::MixedReliability {
        reliable,
        best_effort,
    })
}

/// The best-effort half of a mixed-reliability session: one Zenoh batch per
/// WebTransport datagram, without a length prefix.
pub struct LinkUnicastWebTransportDatagram {
    session: Session,
    connection: QuicConnection,
    src_addr: SocketAddr,
    src_locator: Locator,
    dst_locator: Locator,
    mtu: u16,
    auth_id: LinkAuthId,
}

#[async_trait]
impl LinkUnicastTrait for LinkUnicastWebTransportDatagram {
    async fn close(&self) -> ZResult<()> {
        self.session.close(0, b"close");
        Ok(())
    }

    async fn write(&self, buffer: &[u8], priority: Option<Priority>) -> ZResult<usize> {
        self.write_all(buffer, priority).await?;
        Ok(buffer.len())
    }

    async fn write_all(&self, buffer: &[u8], priority: Option<Priority>) -> ZResult<()> {
        // A refused datagram is shed here, as the network may shed it later:
        // best effort means the write succeeded, not that the bytes arrived.
        if !self.connection.admit_datagram(priority, buffer.len()) {
            return Ok(());
        }
        self.session
            .send_datagram(Bytes::copy_from_slice(buffer))
            .map_err(|e| {
                zerror!("Write error on WebTransport datagram link {}: {}", self, e).into()
            })
    }

    async fn read(&self, buffer: &mut [u8], _priority: Option<Priority>) -> ZResult<usize> {
        let bytes = self
            .session
            .read_datagram()
            .await
            .map_err(|e| zerror!("Read error on WebTransport datagram link {}: {}", self, e))?;
        buffer
            .get_mut(..bytes.len())
            .map(|buffer| buffer.copy_from_slice(&bytes))
            .ok_or_else(|| {
                zerror!(
                    "WebTransport datagram of len {} cannot fit in RX buffer of len {}",
                    bytes.len(),
                    buffer.len()
                )
            })?;
        Ok(bytes.len())
    }

    async fn read_exact(&self, _: &mut [u8], _priority: Option<Priority>) -> ZResult<()> {
        unreachable!("datagram links are not streamed")
    }

    fn get_src(&self) -> &Locator {
        &self.src_locator
    }

    fn get_dst(&self) -> &Locator {
        &self.dst_locator
    }

    fn get_mtu(&self) -> BatchSize {
        // Zenoh negotiates the batch size once, so this must not change.
        self.mtu
    }

    fn get_current_max_datagram_size(&self) -> Option<BatchSize> {
        Some(datagram_mtu(&self.session)).filter(|size| *size > 0)
    }

    fn get_interface_names(&self) -> Vec<String> {
        get_ip_interface_names(&self.src_addr)
    }

    fn is_reliable(&self) -> bool {
        false
    }

    fn is_streamed(&self) -> bool {
        false
    }

    fn get_auth_id(&self) -> &LinkAuthId {
        &self.auth_id
    }

    #[cfg(all(feature = "uring", target_os = "linux"))]
    fn get_fd(&self) -> ZResult<RawFd> {
        bail!("Not supported");
    }
}

impl fmt::Display for LinkUnicastWebTransportDatagram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} => {} (datagrams)",
            self.src_locator, self.dst_locator
        )
    }
}

impl fmt::Debug for LinkUnicastWebTransportDatagram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebTransportDatagram")
            .field("src", &self.src_locator)
            .field("dst", &self.dst_locator)
            .field("mtu", &self.mtu)
            .finish()
    }
}
