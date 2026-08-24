//
// Copyright (c) 2026 Adamo Tech
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//

use std::collections::{HashMap, VecDeque};

use zenoh_protocol::transport::{Fragment, TransportSn};

/// Holds best-effort fragments until a complete marker-delimited message is
/// available. Datagram links may reorder fragments; feeding them directly to
/// `DefragBuffer` turns harmless reordering into an application-layer drop.
#[derive(Debug)]
pub(crate) struct FragmentReorderBuffer {
    fragments: HashMap<TransportSn, Fragment>,
    arrival_order: VecDeque<TransportSn>,
    capacity: usize,
    mask: TransportSn,
}

impl FragmentReorderBuffer {
    pub(crate) fn new(capacity: usize, mask: TransportSn) -> Self {
        Self {
            fragments: HashMap::with_capacity(capacity),
            arrival_order: VecDeque::with_capacity(capacity),
            capacity,
            mask,
        }
    }

    pub(crate) fn clear(&mut self) {
        self.fragments.clear();
        self.arrival_order.clear();
    }

    /// Inserts one fragment and returns every message that became complete.
    /// Each returned vector is ordered by transport sequence number.
    pub(crate) fn insert(&mut self, fragment: Fragment) -> Vec<Vec<Fragment>> {
        let sn = fragment.sn;
        if self.fragments.insert(sn, fragment).is_none() {
            self.arrival_order.push_back(sn);
        }
        self.evict_to_capacity();
        self.take_complete_messages()
    }

    fn evict_to_capacity(&mut self) {
        while self.fragments.len() > self.capacity {
            let Some(sn) = self.arrival_order.pop_front() else {
                break;
            };
            self.fragments.remove(&sn);
        }
    }

    fn take_complete_messages(&mut self) -> Vec<Vec<Fragment>> {
        let starts: Vec<_> = self
            .arrival_order
            .iter()
            .copied()
            .filter(|sn| {
                self.fragments
                    .get(sn)
                    .is_some_and(|fragment| fragment.ext_first.is_some())
            })
            .collect();
        let mut completed = Vec::new();

        for start in starts {
            if !self.fragments.contains_key(&start) {
                continue;
            }
            let mut sns = Vec::new();
            let mut sn = start;
            let mut dropped = false;
            let mut complete = false;

            for index in 0..self.capacity {
                let Some(fragment) = self.fragments.get(&sn) else {
                    break;
                };
                if index != 0 && fragment.ext_first.is_some() {
                    break;
                }
                sns.push(sn);
                if fragment.ext_drop.is_some() {
                    dropped = true;
                    complete = true;
                    break;
                }
                if !fragment.more {
                    complete = true;
                    break;
                }
                sn = sn.wrapping_add(1) & self.mask;
            }

            if !complete {
                continue;
            }
            let message: Vec<_> = sns
                .into_iter()
                .filter_map(|sn| self.fragments.remove(&sn))
                .collect();
            if !dropped {
                completed.push(message);
            }
        }

        // Remove stale arrival records left by completed messages.
        self.arrival_order
            .retain(|sn| self.fragments.contains_key(sn));
        completed
    }
}

#[cfg(test)]
mod tests {
    use zenoh_buffers::ZSlice;
    use zenoh_protocol::{
        core::{Priority, Reliability},
        transport::fragment::{ext, Fragment},
    };

    use super::FragmentReorderBuffer;

    fn fragment(sn: u32, first: bool, more: bool) -> Fragment {
        Fragment {
            reliability: Reliability::BestEffort,
            more,
            sn,
            payload: ZSlice::from(vec![sn as u8]),
            ext_qos: ext::QoSType::new(Priority::DEFAULT),
            ext_first: first.then(ext::First::new),
            ext_drop: None,
        }
    }

    fn sequence(message: &[Fragment]) -> Vec<u32> {
        message.iter().map(|fragment| fragment.sn).collect()
    }

    #[test]
    fn releases_in_order_message() {
        let mut buffer = FragmentReorderBuffer::new(8, 127);
        assert!(buffer.insert(fragment(10, true, true)).is_empty());
        assert!(buffer.insert(fragment(11, false, true)).is_empty());
        let messages = buffer.insert(fragment(12, false, false));
        assert_eq!(messages.len(), 1);
        assert_eq!(sequence(&messages[0]), [10, 11, 12]);
    }

    #[test]
    fn releases_reordered_message_only_after_start_arrives() {
        let mut buffer = FragmentReorderBuffer::new(8, 127);
        assert!(buffer.insert(fragment(12, false, false)).is_empty());
        assert!(buffer.insert(fragment(11, false, true)).is_empty());
        let messages = buffer.insert(fragment(10, true, true));
        assert_eq!(messages.len(), 1);
        assert_eq!(sequence(&messages[0]), [10, 11, 12]);
    }

    #[test]
    fn incomplete_message_does_not_block_new_complete_message() {
        let mut buffer = FragmentReorderBuffer::new(8, 127);
        assert!(buffer.insert(fragment(1, true, true)).is_empty());
        assert!(buffer.insert(fragment(5, true, true)).is_empty());
        let messages = buffer.insert(fragment(6, false, false));
        assert_eq!(messages.len(), 1);
        assert_eq!(sequence(&messages[0]), [5, 6]);
    }

    #[test]
    fn sequence_wrap_is_contiguous() {
        let mut buffer = FragmentReorderBuffer::new(8, 127);
        assert!(buffer.insert(fragment(0, false, false)).is_empty());
        let messages = buffer.insert(fragment(127, true, true));
        assert_eq!(messages.len(), 1);
        assert_eq!(sequence(&messages[0]), [127, 0]);
    }

    #[test]
    fn capacity_evicts_old_incomplete_fragments() {
        let mut buffer = FragmentReorderBuffer::new(3, 127);
        assert!(buffer.insert(fragment(1, true, true)).is_empty());
        assert!(buffer.insert(fragment(2, false, true)).is_empty());
        assert!(buffer.insert(fragment(10, true, true)).is_empty());
        let messages = buffer.insert(fragment(11, false, false));
        assert_eq!(messages.len(), 1);
        assert_eq!(sequence(&messages[0]), [10, 11]);
    }
}
