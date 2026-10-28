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

//! ⚠️ WARNING ⚠️
//!
//! This module is intended for Zenoh's internal use.
//!
//! [Click here for Zenoh's documentation](https://docs.rs/zenoh/latest/zenoh)
//!
//! A runtime switch that holds back data a peer would send to its routers,
//! while its other faces keep receiving it.

use std::{
    any::Any,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use zenoh_config::WhatAmI;
use zenoh_keyexpr::keyexpr;
use zenoh_protocol::network::{NetworkBodyMut, NetworkMessageMut};
use zenoh_transport::{multicast::TransportMulticast, unicast::TransportUnicast};

use super::{
    EgressInterceptor, IngressInterceptor, InterceptorContext, InterceptorFactory,
    InterceptorFactoryTrait, InterceptorTrait,
};

/// Only a peer serves faces of its own besides its routers, so only a peer
/// gets the gate.
pub(crate) fn router_egress_interceptor_factories(
    mode: WhatAmI,
    paused: &Arc<AtomicBool>,
) -> Vec<InterceptorFactory> {
    match mode {
        WhatAmI::Peer => vec![Box::new(RouterEgressFactory {
            paused: paused.clone(),
        })],
        _ => vec![],
    }
}

struct RouterEgressFactory {
    paused: Arc<AtomicBool>,
}

impl InterceptorFactoryTrait for RouterEgressFactory {
    fn new_transport_unicast(
        &self,
        transport: &TransportUnicast,
    ) -> (Option<IngressInterceptor>, Option<EgressInterceptor>) {
        let egress = match transport.get_whatami() {
            Ok(WhatAmI::Router) => Some(Box::new(RouterEgressGate {
                paused: self.paused.clone(),
            }) as EgressInterceptor),
            _ => None,
        };
        (None, egress)
    }

    fn new_transport_multicast(&self, _transport: &TransportMulticast) -> Option<EgressInterceptor> {
        None
    }

    fn new_peer_multicast(&self, _transport: &TransportMulticast) -> Option<IngressInterceptor> {
        None
    }
}

struct RouterEgressGate {
    paused: Arc<AtomicBool>,
}

impl InterceptorTrait for RouterEgressGate {
    fn compute_keyexpr_cache(&self, _key_expr: &keyexpr) -> Option<Box<dyn Any + Send + Sync>> {
        None
    }

    /// Drops publications and query replies while paused. Declarations,
    /// interests and the peer's own queries still flow, so routing state stays
    /// whole and data resumes the moment the gate opens. Final responses still
    /// flow too, so a router's querier sees an empty answer instead of waiting
    /// for its timeout.
    fn intercept(&self, msg: &mut NetworkMessageMut, _ctx: &mut dyn InterceptorContext) -> bool {
        if !self.paused.load(Ordering::Relaxed) {
            return true;
        }
        !matches!(
            msg.body,
            NetworkBodyMut::Push(_) | NetworkBodyMut::Response(_)
        )
    }
}
