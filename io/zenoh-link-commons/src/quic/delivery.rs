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

//! Delivery accounting for one QUIC connection.
//!
//! Quinn reports acknowledged bytes only to the congestion controller, so a
//! thin controller wrapper is the one place they can be counted. Every packet
//! carrying a DATAGRAM frame is ack-eliciting, so the count covers best-effort
//! media as well as streams. The wrapper delegates every decision to the real
//! controller and changes nothing about how the connection behaves.

use std::{
    any::Any,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

use quinn_proto::{
    congestion::{Controller, ControllerFactory, ControllerMetrics},
    RttEstimator,
};

/// Cumulative acknowledged bytes for one connection.
#[derive(Debug, Default)]
pub struct DeliveryCounters {
    delivered_bytes: AtomicU64,
    app_limited_delivered_bytes: AtomicU64,
}

impl DeliveryCounters {
    /// Bytes the peer has acknowledged so far.
    pub fn delivered_bytes(&self) -> u64 {
        self.delivered_bytes.load(Ordering::Relaxed)
    }

    /// The share of [`Self::delivered_bytes`] acknowledged while the
    /// connection was waiting on application data rather than on the
    /// congestion window. Those bytes prove a rate the path can carry, but
    /// not that it could carry no more.
    pub fn app_limited_delivered_bytes(&self) -> u64 {
        self.app_limited_delivered_bytes.load(Ordering::Relaxed)
    }
}

/// Builds a [`DeliveryTracking`] around whatever controller the inner factory
/// builds, feeding one shared set of counters.
pub struct DeliveryTrackingFactory {
    inner: Arc<dyn ControllerFactory + Send + Sync>,
    counters: Arc<DeliveryCounters>,
}

impl DeliveryTrackingFactory {
    pub fn new(
        inner: Arc<dyn ControllerFactory + Send + Sync>,
        counters: Arc<DeliveryCounters>,
    ) -> Self {
        Self { inner, counters }
    }
}

impl ControllerFactory for DeliveryTrackingFactory {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(DeliveryTracking {
            inner: self.inner.clone().build(now, current_mtu),
            counters: self.counters.clone(),
        })
    }
}

struct DeliveryTracking {
    inner: Box<dyn Controller>,
    counters: Arc<DeliveryCounters>,
}

impl Controller for DeliveryTracking {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.inner.on_sent(now, bytes, last_packet_number);
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.counters
            .delivered_bytes
            .fetch_add(bytes, Ordering::Relaxed);
        if app_limited {
            self.counters
                .app_limited_delivered_bytes
                .fetch_add(bytes, Ordering::Relaxed);
        }
        self.inner.on_ack(now, sent, bytes, app_limited, rtt);
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.inner
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.inner
            .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.inner.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        self.inner.window()
    }

    fn metrics(&self) -> ControllerMetrics {
        self.inner.metrics()
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            inner: self.inner.clone_box(),
            counters: self.counters.clone(),
        })
    }

    fn initial_window(&self) -> u64 {
        self.inner.initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}
