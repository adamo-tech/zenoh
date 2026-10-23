// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0

//! Opt-in, connection-local packet observations. Observers cannot alter QUIC
//! congestion control. No process-global callbacks or replay queues are used.
use std::{
    fmt,
    hash::{Hash, Hasher},
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

#[derive(Clone, Copy, Debug)]
pub enum PacketEvent {
    Reset {
        generation: u64,
    },
    Sent {
        now: Instant,
        generation: u64,
        number: u64,
        bytes: u16,
        prior_in_flight: u64,
    },
    Acked {
        generation: u64,
        number: u64,
        bytes: u16,
    },
    Lost {
        generation: u64,
        number: u64,
        bytes: u16,
    },
    Neutered {
        generation: u64,
        number: u64,
    },
    Feedback {
        now: Instant,
        generation: u64,
        prior_in_flight: u64,
        app_limited: bool,
    },
    ApplicationLimited {
        generation: u64,
    },
}

/// Implementations must return promptly and must not panic or reenter Quinn.
pub trait PacketObserver: Send + Sync {
    fn observe(&self, event: PacketEvent);
}

#[derive(Default)]
struct Slot {
    enabled: AtomicBool,
    observer: RwLock<Option<Arc<dyn PacketObserver>>>,
}

/// A capability for one established QUIC connection. Clones refer to the same
/// slot, including the reliable/datagram views of a mixed-reliability link.
#[derive(Clone, Default)]
pub struct PacketObserverHandle(Arc<Slot>);
impl PacketObserverHandle {
    /// Installs once. Returns false when this connection already has an observer.
    pub fn install(&self, observer: Arc<dyn PacketObserver>) -> bool {
        let mut slot = self.0.observer.write().unwrap_or_else(|e| e.into_inner());
        if slot.is_some() {
            return false;
        }
        *slot = Some(observer);
        self.0.enabled.store(true, Ordering::Release);
        true
    }
    pub(crate) fn enabled(&self) -> bool {
        self.0.enabled.load(Ordering::Acquire)
    }
    #[cfg(feature = "quic_delivery_observer")]
    pub(crate) fn observe(&self, event: PacketEvent) {
        let slot = self.0.observer.read().unwrap_or_else(|e| e.into_inner());
        if let Some(observer) = slot.as_ref() {
            observer.observe(event);
        }
    }
}
impl fmt::Debug for PacketObserverHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketObserverHandle")
            .field("enabled", &self.enabled())
            .finish()
    }
}
impl PartialEq for PacketObserverHandle {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for PacketObserverHandle {}
impl Hash for PacketObserverHandle {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.0).hash(state);
    }
}

#[cfg(all(test, feature = "quic_delivery_observer"))]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    struct Count(Arc<AtomicUsize>);
    impl PacketObserver for Count {
        fn observe(&self, _: PacketEvent) { self.0.fetch_add(1, Ordering::Relaxed); }
    }
    #[test]
    fn observers_are_connection_local_and_install_once() {
        let a = PacketObserverHandle::default();
        let b = PacketObserverHandle::default();
        let first = Arc::new(AtomicUsize::new(0));
        let second = Arc::new(AtomicUsize::new(0));
        assert!(a.install(Arc::new(Count(first.clone()))));
        assert!(!a.clone().install(Arc::new(Count(second.clone()))));
        assert!(!b.enabled());
        a.observe(PacketEvent::ApplicationLimited { generation: 0 });
        assert_eq!(first.load(Ordering::Relaxed), 1);
        assert_eq!(second.load(Ordering::Relaxed), 0);
        assert!(b.install(Arc::new(Count(second.clone()))));
        b.observe(PacketEvent::ApplicationLimited { generation: 0 });
        assert_eq!(first.load(Ordering::Relaxed), 1);
        assert_eq!(second.load(Ordering::Relaxed), 1);
    }
}
