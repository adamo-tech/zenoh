//
// Copyright (c) 2026 ZettaScale Technology
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
//! UDP socket buffer sizing for QUIC links.
//!
//! A QUIC stack absorbs bursts in the kernel socket buffer. Whatever does not
//! fit while the process is off the CPU is dropped before quinn ever sees it,
//! and the congestion controller reads those drops as congestion rather than
//! as scheduling delay. The OS defaults are sized for a chatty TCP-era socket
//! (208 KiB on Linux), which one socket carrying a media connection can cross
//! in milliseconds, and a robot's encoder competes for the CPU with capture,
//! vision and control loops, so the gaps between polls are neither short nor
//! predictable.
//!
//! The size is compiled in rather than derived from the link: the buffer is a
//! ceiling on queued bytes rather than an allocation, so an oversized request
//! costs an idle socket nothing, while a link's nominal speed says little
//! about the path it feeds. It can still be overridden per endpoint.

use std::sync::atomic::{AtomicBool, Ordering};

use socket2::SockRef;
use tokio::net::UdpSocket;
use tracing::warn;
use zenoh_protocol::core::endpoint::Config;
use zenoh_result::{zerror, ZResult};

/// Endpoint config key overriding the requested `SO_SNDBUF`, in bytes.
pub const QUIC_UDP_SEND_BUFFER: &str = "udp_send_buffer";
/// Endpoint config key overriding the requested `SO_RCVBUF`, in bytes.
pub const QUIC_UDP_RECV_BUFFER: &str = "udp_recv_buffer";

/// Requested UDP socket buffer per direction.
///
/// Roughly 64 ms of a saturated 1 Gbps link: generous next to a scheduler
/// delay and cheap next to what a connection already costs. quic-go asks for
/// 7 MiB for the same reason.
pub const QUIC_UDP_BUFFER_BYTES: usize = 8 * 1024 * 1024;

/// The sysctl an operator raises when the kernel clamps our request.
#[cfg(any(target_os = "linux", target_os = "android"))]
const RECV_SYSCTL: &str = "net.core.rmem_max";
#[cfg(any(target_os = "linux", target_os = "android"))]
const SEND_SYSCTL: &str = "net.core.wmem_max";
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const RECV_SYSCTL: &str = "kern.ipc.maxsockbuf";
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const SEND_SYSCTL: &str = "kern.ipc.maxsockbuf";

/// One warning per direction per process: a client that reconnects rebinds,
/// and the operator only needs telling once.
static RECV_WARNED: AtomicBool = AtomicBool::new(false);
static SEND_WARNED: AtomicBool = AtomicBool::new(false);

/// Linux reports back double what it granted, reserving the other half for
/// per-packet bookkeeping, so halving keeps the numbers we compare and log in
/// the same units an operator writes into the sysctl.
const fn granted(reported: usize) -> usize {
    if cfg!(any(target_os = "linux", target_os = "android")) {
        reported / 2
    } else {
        reported
    }
}

/// Requested buffer sizes for a QUIC link's UDP socket.
#[derive(Clone, Copy, Debug)]
pub struct QuicUdpBufferConfig {
    send: usize,
    recv: usize,
}

impl Default for QuicUdpBufferConfig {
    fn default() -> Self {
        Self {
            send: QUIC_UDP_BUFFER_BYTES,
            recv: QUIC_UDP_BUFFER_BYTES,
        }
    }
}

impl QuicUdpBufferConfig {
    /// Apply the requested sizes to `socket`, best effort.
    ///
    /// Reading the size back is the whole point: Linux silently clamps the
    /// request to its sysctl, so `setsockopt` returning `Ok` says nothing
    /// about the size we ended up with, and `SO_RCVBUFFORCE` (the clamp-free
    /// version) needs a `CAP_NET_ADMIN` a media process should not be asking
    /// for. A socket that a tuned system already sized above our request is
    /// left alone.
    pub fn apply(&self, socket: &UdpSocket) {
        let socket = SockRef::from(socket);

        apply_one(
            self.recv,
            || socket.recv_buffer_size(),
            |size| socket.set_recv_buffer_size(size),
            "receive",
            RECV_SYSCTL,
            &RECV_WARNED,
        );
        apply_one(
            self.send,
            || socket.send_buffer_size(),
            |size| socket.set_send_buffer_size(size),
            "send",
            SEND_SYSCTL,
            &SEND_WARNED,
        );
    }
}

fn apply_one(
    requested: usize,
    get: impl Fn() -> std::io::Result<usize>,
    set: impl Fn(usize) -> std::io::Result<()>,
    name: &str,
    sysctl: &str,
    warned: &AtomicBool,
) {
    // Never shrink a system that is already tuned above our default.
    if matches!(get(), Ok(current) if granted(current) >= requested) {
        return;
    }

    if let Err(err) = set(requested) {
        if !warned.swap(true, Ordering::Relaxed) {
            warn!("failed to set the UDP {name} buffer to {requested} bytes: {err}");
        }
        return;
    }

    match get() {
        Ok(reported) if granted(reported) < requested => {
            if !warned.swap(true, Ordering::Relaxed) {
                warn!(
                    "UDP {name} buffer is {} bytes, smaller than the requested {requested}; \
                     raise `{sysctl}` or expect packet loss under load",
                    granted(reported)
                );
            }
        }
        Ok(_) => {}
        Err(err) => {
            if !warned.swap(true, Ordering::Relaxed) {
                warn!("could not read back the UDP {name} buffer size: {err}");
            }
        }
    }
}

impl TryFrom<&Config<'_>> for QuicUdpBufferConfig {
    type Error = zenoh_result::Error;

    fn try_from(config: &Config) -> ZResult<Self> {
        let mut buffers = Self::default();

        if let Some(v) = config.get(QUIC_UDP_SEND_BUFFER) {
            buffers.send = parse_size(v, QUIC_UDP_SEND_BUFFER)?;
        }
        if let Some(v) = config.get(QUIC_UDP_RECV_BUFFER) {
            buffers.recv = parse_size(v, QUIC_UDP_RECV_BUFFER)?;
        }

        Ok(buffers)
    }
}

fn parse_size(value: &str, key: &str) -> ZResult<usize> {
    let size = value
        .parse::<usize>()
        .map_err(|err| zerror!("could not parse QUIC endpoint's {key} value `{value}`: {err}"))?;
    if size == 0 {
        return Err(zerror!("QUIC endpoint's {key} must be greater than zero").into());
    }
    Ok(size)
}

#[cfg(test)]
mod tests {
    use zenoh_protocol::core::EndPoint;

    use super::*;

    fn config_of(endpoint: &str) -> QuicUdpBufferConfig {
        let endpoint: EndPoint = endpoint.parse().unwrap();
        QuicUdpBufferConfig::try_from(&endpoint.config()).unwrap()
    }

    #[test]
    fn defaults_apply_when_the_endpoint_is_silent() {
        let buffers = config_of("quic/127.0.0.1:7447");
        assert_eq!(buffers.send, QUIC_UDP_BUFFER_BYTES);
        assert_eq!(buffers.recv, QUIC_UDP_BUFFER_BYTES);
    }

    #[test]
    fn each_direction_is_overridden_on_its_own() {
        let buffers = config_of("quic/127.0.0.1:7447#udp_recv_buffer=131072");
        assert_eq!(buffers.recv, 131_072);
        assert_eq!(
            buffers.send, QUIC_UDP_BUFFER_BYTES,
            "the direction that was not named keeps the default"
        );
    }

    #[test]
    fn a_zero_buffer_is_rejected_rather_than_disabling_the_socket() {
        let endpoint: EndPoint = "quic/127.0.0.1:7447#udp_send_buffer=0".parse().unwrap();
        assert!(QuicUdpBufferConfig::try_from(&endpoint.config()).is_err());
    }

    #[test]
    fn a_non_numeric_buffer_is_rejected() {
        let endpoint: EndPoint = "quic/127.0.0.1:7447#udp_recv_buffer=large".parse().unwrap();
        assert!(QuicUdpBufferConfig::try_from(&endpoint.config()).is_err());
    }

    #[tokio::test]
    async fn applying_never_shrinks_a_socket() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let before = {
            let socket = SockRef::from(&socket);
            (
                socket.recv_buffer_size().unwrap(),
                socket.send_buffer_size().unwrap(),
            )
        };

        QuicUdpBufferConfig::default().apply(&socket);

        let after = {
            let socket = SockRef::from(&socket);
            (
                socket.recv_buffer_size().unwrap(),
                socket.send_buffer_size().unwrap(),
            )
        };
        assert!(
            after.0 >= before.0,
            "receive buffer shrank from {} to {}",
            before.0,
            after.0
        );
        assert!(
            after.1 >= before.1,
            "send buffer shrank from {} to {}",
            before.1,
            after.1
        );
    }

    #[tokio::test]
    async fn a_request_below_what_the_socket_has_is_left_alone() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        QuicUdpBufferConfig::default().apply(&socket);
        let raised = SockRef::from(&socket).recv_buffer_size().unwrap();

        // A later link asking for a tiny buffer must not undo the tuning.
        QuicUdpBufferConfig {
            send: 8 * 1024,
            recv: 8 * 1024,
        }
        .apply(&socket);

        assert_eq!(SockRef::from(&socket).recv_buffer_size().unwrap(), raised);
    }
}
