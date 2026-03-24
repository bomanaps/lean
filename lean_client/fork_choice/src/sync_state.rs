#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SyncState {
    #[default]
    Idle,
    Syncing,
    Synced,
}

impl SyncState {
    pub fn accepts_gossip(self) -> bool {
        matches!(self, SyncState::Syncing | SyncState::Synced)
    }

    pub fn is_idle(self) -> bool {
        self == SyncState::Idle
    }

    pub fn is_syncing(self) -> bool {
        self == SyncState::Syncing
    }

    pub fn is_synced(self) -> bool {
        self == SyncState::Synced
    }
}
