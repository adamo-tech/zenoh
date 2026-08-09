//
// Copyright (c) 2026 Adamo Technology Ltd.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//

//! Native Zenoh links over WebTransport.

use std::str::FromStr;

use async_trait::async_trait;
use zenoh_core::zconfigurable;
use zenoh_link_commons::LocatorInspector;
use zenoh_protocol::{
    core::{Locator, Metadata, Reliability},
    transport::BatchSize,
};
use zenoh_result::ZResult;

mod unicast;
pub use unicast::*;
pub use zenoh_link_commons::quic::TlsConfigurator as WebTransportConfigurator;

pub const WEBTRANSPORT_LOCATOR_PREFIX: &str = "webtransport";
pub const WEBTRANSPORT_PATH_CONFIG: &str = "path";
pub const WEBTRANSPORT_SERVER_CERTIFICATE_HASH_CONFIG: &str = "server_certificate_hash";
pub const WEBTRANSPORT_JWT_PUBLIC_KEY_FILE_CONFIG: &str = "jwt_public_key_file";
pub const WEBTRANSPORT_JWT_AUDIENCE_CONFIG: &str = "jwt_audience";
pub const WEBTRANSPORT_DEFAULT_PATH: &str = "/zenoh";

const IS_RELIABLE: bool = true;
const WEBTRANSPORT_MAX_MTU: BatchSize = BatchSize::MAX;

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

    fn is_reliable(&self, locator: &Locator) -> ZResult<bool> {
        if let Some(reliability) = locator
            .metadata()
            .get(Metadata::RELIABILITY)
            .map(Reliability::from_str)
            .transpose()?
        {
            Ok(reliability == Reliability::Reliable)
        } else {
            Ok(IS_RELIABLE)
        }
    }
}

zconfigurable! {
    static ref WEBTRANSPORT_DEFAULT_MTU: BatchSize = WEBTRANSPORT_MAX_MTU;
    static ref WEBTRANSPORT_ACCEPT_THROTTLE_TIME: u64 = 100_000;
}
