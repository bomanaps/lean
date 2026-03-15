use std::{collections::HashMap, fmt::Display, sync::Arc};

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use containers::{
    AggregatedSignatureProof, AttestationData, Block, SignedAggregatedAttestation,
    SignedAttestation, SignedBlockWithAttestation, Slot, Status,
};
use metrics::METRICS;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use ssz::H256;
use tokio::sync::{mpsc, oneshot};
use tracing::warn;

use crate::serde_utils::quoted_u64;

/// Shared block provider for serving BlocksByRoot requests.
/// Allows NetworkService to look up signed blocks for checkpoint sync backfill.
pub type SignedBlockProvider = Arc<RwLock<HashMap<H256, SignedBlockWithAttestation>>>;

/// Shared status provider for Status req/resp protocol.
/// Allows NetworkService to send accurate finalized/head checkpoints to peers.
pub type StatusProvider = Arc<RwLock<Status>>;

/// 1-byte domain for gossip message-id isolation of valid snappy messages.
/// Per leanSpec, prepended to the message hash when decompression succeeds.
pub const MESSAGE_DOMAIN_VALID_SNAPPY: &[u8; 1] = &[0x01];

/// 1-byte domain for gossip message-id isolation of invalid snappy messages.
/// Per leanSpec, prepended to the message hash when decompression fails.
pub const MESSAGE_DOMAIN_INVALID_SNAPPY: &[u8; 1] = &[0x00];

/// Peer connection state machine per leanSpec.
///
/// Tracks the lifecycle of a connection to a peer:
/// DISCONNECTED -> CONNECTING -> CONNECTED -> DISCONNECTING -> DISCONNECTED
///
/// These states map directly to libp2p connection events.
#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionState {
    /// No active connection to this peer.
    Disconnected,
    /// TCP/QUIC connection in progress.
    Connecting,
    /// Transport established, can exchange protocol messages.
    Connected,
    /// Graceful shutdown in progress (Goodbye sent/received).
    Disconnecting,
}

/// Reason codes for the Goodbye request/response message per leanSpec.
///
/// Sent when gracefully disconnecting from a peer to indicate why
/// the connection is being closed.
///
/// Official codes (from spec):
/// - 1: Client shutdown
/// - 2: Irrelevant network
/// - 3: Fault/error
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u64)]
pub enum GoodbyeReason {
    /// Node is shutting down normally.
    ClientShutdown = 1,
    /// Peer is on a different fork or network.
    IrrelevantNetwork = 2,
    /// Generic error detected in peer communication.
    FaultOrError = 3,
}

impl GoodbyeReason {
    /// Convert from u64 code to GoodbyeReason.
    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(GoodbyeReason::ClientShutdown),
            2 => Some(GoodbyeReason::IrrelevantNetwork),
            3 => Some(GoodbyeReason::FaultOrError),
            _ => None,
        }
    }

    /// Get the u64 code for this reason.
    pub fn code(&self) -> u64 {
        *self as u64
    }
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Inbound,
    Outbound,
    Unknown,
}

#[derive(Default, Debug, Clone, Serialize)]
pub struct PeerCount {
    #[serde(with = "quoted_u64")]
    pub disconnected: u64,
    #[serde(with = "quoted_u64")]
    pub connecting: u64,
    #[serde(with = "quoted_u64")]
    pub connected: u64,
    #[serde(with = "quoted_u64")]
    pub disconnecting: u64,
}

impl PeerCount {
    pub fn new(states: &HashMap<libp2p_identity::PeerId, ConnectionState>) -> Self {
        let mut count = PeerCount::default();
        for state in states.values() {
            match state {
                ConnectionState::Connected => count.connected += 1,
                ConnectionState::Connecting => count.connecting += 1,
                ConnectionState::Disconnected => count.disconnected += 1,
                ConnectionState::Disconnecting => count.disconnecting += 1,
            }
        }

        METRICS.get().map(|metrics| {
            let Ok(connected) = count.connected.try_into() else {
                warn!("failed to set connected pear count metric");
                return;
            };

            // TODO(metrics): actual client names should be provided into with_label_values
            metrics
                .lean_connected_peers
                .with_label_values(&["unknown"])
                .set(connected);
        });

        count
    }
}

#[derive(Debug, Clone)]
pub enum ChainMessage {
    ProcessBlock {
        signed_block_with_attestation: SignedBlockWithAttestation,
        is_trusted: bool,
        should_gossip: bool,
    },
    ProcessAttestation {
        signed_attestation: SignedAttestation,
        is_trusted: bool,
        should_gossip: bool,
    },
    /// Devnet-3: Process aggregated attestation from aggregation topic
    ProcessAggregation {
        signed_aggregated_attestation: SignedAggregatedAttestation,
        is_trusted: bool,
        should_gossip: bool,
    },
}

impl ChainMessage {
    pub fn block_with_attestation(
        signed_block_with_attestation: SignedBlockWithAttestation,
    ) -> Self {
        ChainMessage::ProcessBlock {
            signed_block_with_attestation,
            is_trusted: false,
            should_gossip: true,
        }
    }

    pub fn attestation(signed_attestation: SignedAttestation) -> Self {
        ChainMessage::ProcessAttestation {
            signed_attestation,
            is_trusted: false,
            should_gossip: true,
        }
    }
}

impl Display for ChainMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainMessage::ProcessBlock {
                signed_block_with_attestation,
                ..
            } => {
                write!(
                    f,
                    "ProcessBlockWithAttestation(slot={})",
                    signed_block_with_attestation.message.block.slot.0
                )
            }
            ChainMessage::ProcessAttestation {
                signed_attestation, ..
            } => {
                write!(
                    f,
                    "ProcessAttestation(slot={})",
                    signed_attestation.message.slot.0
                )
            }
            ChainMessage::ProcessAggregation {
                signed_aggregated_attestation,
                ..
            } => {
                write!(
                    f,
                    "ProcessAggregation(slot={})",
                    signed_aggregated_attestation.data.slot.0
                )
            }
        }
    }
}

/// Messages from the validator task to the chain task (request-response pattern).
/// This keeps `ChainMessage` Clone-able (for network use) while these variants
/// carry non-Clone oneshot senders.
#[derive(Debug)]
pub enum ValidatorChainMessage {
    /// Request block production for the given slot.
    /// Chain executes the state transition under write lock (fast, no XMSS signing)
    /// and returns the raw block + aggregated signature proofs via the sender.
    /// XMSS signing is performed by the validator task after receiving the response,
    /// so the chain task is free to process incoming peer messages during signing.
    ProduceBlock {
        slot: Slot,
        proposer_index: u64,
        sender: oneshot::Sender<Result<(Block, Vec<AggregatedSignatureProof>)>>,
    },
    /// Request attestation data for the given slot.
    /// Chain reads the current head/justified/target state and returns it via sender.
    /// The validator task uses this data to sign attestations without holding the store lock.
    BuildAttestationData {
        slot: Slot,
        sender: oneshot::Sender<Result<AttestationData>>,
    },
}

#[derive(Debug, Clone)]
pub enum OutboundP2pRequest {
    GossipBlockWithAttestation(SignedBlockWithAttestation),
    /// Devnet-3: Gossip attestation to subnet-specific topic
    /// Contains (attestation, subnet_id)
    GossipAttestation(SignedAttestation, u64),
    /// Devnet-3: Gossip aggregated attestation to aggregation topic
    GossipAggregation(SignedAggregatedAttestation),
    RequestBlocksByRoot(Vec<H256>),
}

#[async_trait]
pub trait ChainMessageSink<M>: Send + Sync + Clone {
    async fn send(&self, message: M) -> Result<()>;
}

#[async_trait]
impl<M: Send + 'static> ChainMessageSink<M> for mpsc::UnboundedSender<M> {
    async fn send(&self, message: M) -> Result<()> {
        self.send(message)
            .map_err(|err| anyhow!("failed to send message to chain: {err}"))
    }
}

#[async_trait]
pub trait P2pRequestSource<T>: Send {
    async fn recv(&mut self) -> Option<T>;
}

#[async_trait]
impl<T: Send + 'static> P2pRequestSource<T> for mpsc::UnboundedReceiver<T> {
    async fn recv(&mut self) -> Option<T> {
        mpsc::UnboundedReceiver::recv(self).await
    }
}
