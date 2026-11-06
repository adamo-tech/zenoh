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
    observer: crate::PacketObserverHandle,
    delivered_bytes: AtomicU64,
    app_limited_delivered_bytes: AtomicU64,
    datagrams_shed: AtomicU64,
}

impl DeliveryCounters {
    pub fn packet_observer(&self) -> crate::PacketObserverHandle {
        self.observer.clone()
    }

    /// Datagrams refused at admission because the send queue had fewer free
    /// bytes than the reserve kept for the top priorities.
    ///
    /// A shed is deliberate and local: the frame never entered the queue, so
    /// it cost the link nothing. It is the signal that lower-priority traffic
    /// is being offered faster than the window drains it.
    pub fn datagrams_shed(&self) -> u64 {
        self.datagrams_shed.load(Ordering::Relaxed)
    }

    pub(crate) fn record_shed(&self) {
        self.datagrams_shed.fetch_add(1, Ordering::Relaxed);
    }

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
    fn name(&self) -> &'static str {
        self.inner.name()
    }
    fn supports_ecn(&self) -> bool {
        self.inner.supports_ecn()
    }
    fn set_initial_rtt(&mut self, rtt: std::time::Duration) {
        self.inner.set_initial_rtt(rtt);
    }

    fn clone_for_path(&self, now: Instant) -> Box<dyn Controller> {
        Box::new(Self {
            inner: self.inner.clone_for_path(now),
            counters: self.counters.clone(),
        })
    }
    fn uses_native_pacing(&self) -> bool {
        self.inner.uses_native_pacing()
    }
    fn send_schedule(&mut self, now: Instant, in_flight: u64) -> quinn_proto::congestion::SendSchedule {
        self.inner.send_schedule(now, in_flight)
    }
    fn pacing_rate(&self) -> Option<u64> {
        self.inner.pacing_rate()
    }
    fn shared_model(&self) -> Option<quinn_proto::congestion::SharedModel> {
        self.inner.shared_model()
    }
    fn control_error(&self) -> Option<&'static str> {
        self.inner.control_error()
    }
    fn on_control_event(&mut self, event: quinn_proto::congestion::ControlEvent) {
        let event = if matches!(
            event,
            quinn_proto::congestion::ControlEvent::ApplicationLimited { .. }
        ) && self.counters.observer.production_held() {
            quinn_proto::congestion::ControlEvent::ProductionHeld
        } else {
            event
        };
        self.inner.on_control_event(event);
        #[cfg(feature = "quic_delivery_observer")]
        if let Some(model) = self.inner.shared_model() {
            self.counters
                .observer
                .observe(crate::PacketEvent::SharedModel { model });
        }
    }

    #[cfg(feature = "quic_delivery_observer")]
    fn wants_packet_events(&self) -> bool {
        self.counters.observer.enabled()
    }

    #[cfg(feature = "quic_delivery_observer")]
    fn on_packet_event(&mut self, event: quinn_proto::congestion::PacketEvent) {
        use crate::PacketEvent as P;
        use quinn_proto::congestion::PacketEvent as Q;
        let event = match event {
            Q::StreamBuffer { unacked_bytes } => P::StreamBuffer { unacked_bytes },
            Q::Reset { generation } => P::Reset { generation },
            Q::Sent {
                now,
                generation,
                number,
                bytes,
                prior_in_flight,
            } => P::Sent {
                now,
                generation,
                number,
                bytes,
                prior_in_flight,
            },
            Q::Acked {
                generation,
                number,
                bytes,
            } => P::Acked {
                generation,
                number,
                bytes,
            },
            Q::Lost {
                generation,
                number,
                bytes,
            } => P::Lost {
                generation,
                number,
                bytes,
            },
            Q::Neutered { generation, number } => P::Neutered { generation, number },
            Q::Feedback {
                now,
                generation,
                prior_in_flight,
                app_limited,
            } => P::Feedback {
                now,
                generation,
                prior_in_flight,
                app_limited,
            },
            Q::ApplicationLimited { generation } => P::ApplicationLimited { generation },
        };
        self.counters.observer.observe(event);
    }

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

#[cfg(test)]
mod controller_tests {
    use super::*;
    struct Probe(Arc<AtomicU64>);
    impl Controller for Probe {
        fn name(&self) -> &'static str {
            "forwarding-probe"
        }
        fn supports_ecn(&self) -> bool {
            false
        }
        fn set_initial_rtt(&mut self, rtt: std::time::Duration) {
            self.0.store(rtt.as_micros() as u64, Ordering::Relaxed);
        }
        fn uses_native_pacing(&self) -> bool {
            true
        }
        fn send_schedule(&mut self, now: Instant, _: u64) -> quinn_proto::congestion::SendSchedule {
            quinn_proto::congestion::SendSchedule::PacedUntil(now + std::time::Duration::from_micros(123))
        }
        fn pacing_rate(&self) -> Option<u64> {
            Some(12345)
        }
        fn on_control_event(&mut self, event: quinn_proto::congestion::ControlEvent) {
            self.0.fetch_add(if matches!(event, quinn_proto::congestion::ControlEvent::ProductionHeld) { 10 } else { 1 }, Ordering::Relaxed);
        }
        fn on_congestion_event(&mut self, _: Instant, _: Instant, _: bool, _: u64) {}
        fn on_mtu_update(&mut self, _: u16) {}
        fn window(&self) -> u64 {
            12000
        }
        fn initial_window(&self) -> u64 {
            12000
        }
        fn clone_box(&self) -> Box<dyn Controller> {
            Box::new(Self(self.0.clone()))
        }
        fn into_any(self: Box<Self>) -> Box<dyn Any> {
            self
        }
    }
    #[test]
    fn controller_forwarding_preserves_control_contract() {
        let seen = Arc::new(AtomicU64::new(0));
        let mut wrapper = DeliveryTracking {
            inner: Box::new(Probe(seen.clone())),
            counters: Arc::new(DeliveryCounters::default()),
        };
        assert_eq!(wrapper.name(), "forwarding-probe");
        assert!(!wrapper.supports_ecn());
        assert_eq!(wrapper.pacing_rate(), Some(12345));
        assert!(wrapper.uses_native_pacing());
        let now = Instant::now();
        assert_eq!(wrapper.send_schedule(now, 0), quinn_proto::congestion::SendSchedule::PacedUntil(now + std::time::Duration::from_micros(123)));
        wrapper.set_initial_rtt(std::time::Duration::from_micros(7000));
        assert_eq!(seen.load(Ordering::Relaxed), 7000);
        wrapper.on_control_event(quinn_proto::congestion::ControlEvent::ApplicationLimited {
            in_flight: 0,
        });
        assert_eq!(seen.load(Ordering::Relaxed), 7001);
        wrapper.counters.observer.hold_production(std::time::Duration::from_secs(1));
        wrapper.on_control_event(quinn_proto::congestion::ControlEvent::ApplicationLimited { in_flight: 0 });
        assert_eq!(seen.load(Ordering::Relaxed), 7011, "transport hold must stop pacing catch-up without marking BBR source-limited");
        let cloned = wrapper.clone_for_path(Instant::now());
        assert_eq!(cloned.name(), "forwarding-probe");
        assert_eq!(cloned.pacing_rate(), Some(12345));
    }
}
