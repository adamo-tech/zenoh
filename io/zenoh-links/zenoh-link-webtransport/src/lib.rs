//
// Copyright (c) 2026 Adamo Technology Ltd.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//

use async_trait::async_trait;
use zenoh_core::zconfigurable;
use zenoh_link_commons::LocatorInspector;
use zenoh_protocol::{core::Locator, transport::BatchSize};
use zenoh_result::ZResult;

mod unicast;
pub use unicast::*;

pub const WEBTRANSPORT_LOCATOR_PREFIX: &str = "webtransport";
pub const WEBTRANSPORT_PATH: &str = "path";
pub const WEBTRANSPORT_TICKET: &str = "ticket";
pub const WEBTRANSPORT_SERVER_CERTIFICATE_HASH: &str = "server_certificate_hash";
pub const WEBTRANSPORT_TICKET_PUBLIC_KEY_FILE: &str = "ticket_public_key_file";
pub const WEBTRANSPORT_TICKET_ISSUER: &str = "ticket_issuer";
pub const WEBTRANSPORT_TICKET_AUDIENCE: &str = "ticket_audience";
pub const WEBTRANSPORT_ALLOWED_ORIGINS: &str = "allowed_origins";
pub const WEBTRANSPORT_CLIENT_ORIGIN: &str = "client_origin";
pub const WEBTRANSPORT_DEFAULT_PATH: &str = "/zenoh";

#[derive(Default, Clone, Copy, Debug)]
pub struct WebTransportLocatorInspector;

#[async_trait]
impl LocatorInspector for WebTransportLocatorInspector {
    fn protocol(&self) -> &str {
        WEBTRANSPORT_LOCATOR_PREFIX
    }

    async fn is_multicast(&self, _locator: &Locator) -> ZResult<bool> {
        Ok(false)
    }

    fn is_reliable(&self, _locator: &Locator) -> ZResult<bool> {
        Ok(true)
    }
}

zconfigurable! {
    static ref WEBTRANSPORT_DEFAULT_MTU: BatchSize = BatchSize::MAX;
}
