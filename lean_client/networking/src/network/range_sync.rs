use std::collections::HashMap;
use std::ops::Range;

use libp2p_identity::PeerId;

use crate::req_resp;

/// Cap on slots covered by a single long-range sync session.
pub const MAX_SYNC_RANGE: u64 = req_resp::MAX_REQUEST_BLOCKS as u64 * 64;

/// Long-range sync session triggered when a peer's Status reveals it is ahead.
pub(crate) struct RangeSyncState {
    pub current_range: Range<u64>,
    pub peer_set: HashMap<PeerId, u64>,
    pub in_flight: bool,
}

impl RangeSyncState {
    pub fn new(current_range: Range<u64>, peer: PeerId, peer_head: u64) -> Self {
        Self {
            current_range,
            peer_set: HashMap::from([(peer, peer_head)]),
            in_flight: false,
        }
    }

    pub fn merge_peer(&mut self, peer: PeerId, peer_head: u64, end_exclusive: u64) {
        self.peer_set.insert(peer, peer_head);
        self.current_range.end = self.current_range.end.max(end_exclusive);
        self.drop_stale_peers();
    }

    pub fn next_batch(&self) -> Option<(PeerId, Range<u64>)> {
        if self.in_flight || self.current_range.is_empty() {
            return None;
        }
        let (&peer, &peer_head) = self
            .peer_set
            .iter()
            .filter(|(_, head)| **head >= self.current_range.start)
            .max_by_key(|(_, head)| **head)?;
        let peer_end = peer_head.saturating_add(1);
        let batch_end = self
            .current_range
            .start
            .saturating_add(req_resp::MAX_REQUEST_BLOCKS as u64)
            .min(self.current_range.end)
            .min(peer_end);
        (batch_end > self.current_range.start)
            .then_some((peer, self.current_range.start..batch_end))
    }

    pub fn complete_batch(&mut self, end_slot: u64) {
        self.in_flight = false;
        self.current_range.start = self.current_range.start.max(end_slot.saturating_add(1));
        self.drop_stale_peers();
    }

    pub fn fail_peer(&mut self, peer: &PeerId) {
        self.in_flight = false;
        self.peer_set.remove(peer);
        self.drop_stale_peers();
    }

    fn drop_stale_peers(&mut self) {
        let start_slot = self.current_range.start;
        self.peer_set.retain(|_, head| *head >= start_slot);
    }
}
