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

//! ⚠️ WARNING ⚠️
//!
//! This crate is intended for Zenoh's internal use.
//!
//! [Click here for Zenoh's documentation](https://docs.rs/zenoh/latest/zenoh)

use async_trait::async_trait;
use zenoh_core::zconfigurable;
use zenoh_link_commons::LocatorInspector;
use zenoh_protocol::{core::Locator, transport::BatchSize};
use zenoh_result::ZResult;

// mod unicast;
// pub use unicast::*;

// WebTransport is a byte-stream link: zenoh batches are length-prefixed with
// 16 bits, so the usable MTU is capped at BatchSize::MAX (65535).
#[allow(dead_code)]
const WEBTRANSPORT_MAX_MTU: BatchSize = BatchSize::MAX;
pub const WEBTRANSPORT_LOCATOR_PREFIX: &str = "webtransport";

const IS_RELIABLE: bool = true;

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
        Ok(IS_RELIABLE)
    }
}

zconfigurable! {
    // Default MTU in bytes.
    static ref WEBTRANSPORT_DEFAULT_MTU: BatchSize = WEBTRANSPORT_MAX_MTU;
}

#[cfg(test)]
mod tests {
    use zenoh_link_commons::LocatorInspector as _;
    use zenoh_protocol::core::Locator;

    use super::*;

    #[test]
    fn inspector_defaults() {
        let inspector = WebTransportLocatorInspector;
        assert_eq!(inspector.protocol(), WEBTRANSPORT_LOCATOR_PREFIX);
        let locator = Locator::new(WEBTRANSPORT_LOCATOR_PREFIX, "127.0.0.1:7447", "").unwrap();
        assert!(inspector.is_reliable(&locator).unwrap());
    }
}
