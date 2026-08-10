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
use std::{fmt, net::SocketAddr};

use async_trait::async_trait;
use tokio::sync::Mutex as AsyncMutex;
use web_transport_quinn::{RecvStream, SendStream, Session};
use zenoh_core::zasynclock;
use zenoh_link_commons::{get_ip_interface_names, LinkAuthId, LinkUnicastTrait};
use zenoh_protocol::{
    core::{Locator, Priority},
    transport::BatchSize,
};
#[cfg(all(feature = "uring", target_os = "linux"))]
use zenoh_result::bail;
use zenoh_result::{zerror, ZResult};

use super::{WEBTRANSPORT_DEFAULT_MTU, WEBTRANSPORT_LOCATOR_PREFIX};

pub struct LinkUnicastWebTransport {
    session: Session,
    send: AsyncMutex<SendStream>,
    recv: AsyncMutex<RecvStream>,
    src_addr: SocketAddr,
    src_locator: Locator,
    dst_addr: SocketAddr,
    dst_locator: Locator,
    auth_id: LinkAuthId,
}

impl LinkUnicastWebTransport {
    #[allow(dead_code)]
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
        }
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
