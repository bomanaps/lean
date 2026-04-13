use std::collections::HashSet;

use libp2p::gossipsub::{IdentTopic, TopicHash};

pub const TOPIC_PREFIX: &str = "leanconsensus";
pub const SSZ_SNAPPY_ENCODING_POSTFIX: &str = "ssz_snappy";

pub const BLOCK_TOPIC: &str = "block";
pub const ATTESTATION_SUBNET_PREFIX: &str = "attestation_";
pub const AGGREGATION_TOPIC: &str = "aggregation";

/// Compute the subnet ID for a validator (devnet-3)
/// Subnet assignment: validator_id % subnet_count
pub fn compute_subnet_id(validator_id: u64, subnet_count: u64) -> u64 {
    validator_id % subnet_count.max(1)
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct GossipsubTopic {
    pub fork: String,
    pub kind: GossipsubKind,
}

/// Devnet-3 gossipsub topic kinds
/// Note: Legacy global "attestation" topic removed - use AttestationSubnet(subnet_id) instead
#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub enum GossipsubKind {
    Block,
    /// Subnet-specific attestation topic (devnet-3)
    /// Format: attestation_{subnet_id}
    AttestationSubnet(u64),
    /// Aggregated attestation topic (devnet-3)
    Aggregation,
}

impl GossipsubKind {
    /// Check if this kind matches another, treating AttestationSubnet as matching any subnet
    pub fn matches(&self, other: &Self) -> bool {
        match (self, other) {
            (GossipsubKind::AttestationSubnet(_), GossipsubKind::AttestationSubnet(_)) => true,
            _ => self == other,
        }
    }
}

/// Get gossipsub topics for subscription based on validator role.
///
/// Subscription rules (aligned with leanSpec PR #482):
/// - Block and Aggregation topics: always subscribed.
/// - Attestation subnet topics:
///   - All nodes with registered validators subscribe to each validator's derived subnet.
///   - Aggregators additionally subscribe to any explicit `aggregate_subnet_ids`.
///   - Aggregators with no registered validators fall back to subnet 0.
///   - Non-aggregator nodes with no validators subscribe to no attestation topics
///     (subnet filtering happens at the p2p subscription layer).
pub fn get_subscription_topics(
    fork: String,
    validator_ids: &[u64],
    is_aggregator: bool,
    aggregate_subnet_ids: &[u64],
    subnet_count: u64,
) -> Vec<GossipsubTopic> {
    let mut topics = vec![
        GossipsubTopic {
            fork: fork.clone(),
            kind: GossipsubKind::Block,
        },
        GossipsubTopic {
            fork: fork.clone(),
            kind: GossipsubKind::Aggregation,
        },
    ];

    // Build the set of attestation subnets to subscribe to.
    let mut subscription_subnets: HashSet<u64> = HashSet::new();

    // All nodes with registered validators subscribe to each validator's derived subnet.
    for &vid in validator_ids {
        subscription_subnets.insert(compute_subnet_id(vid, subnet_count));
    }

    // Aggregators add explicit subnet IDs on top of validator-derived ones.
    // If the aggregator has no registered validators, fall back to subnet 0.
    if is_aggregator {
        if subscription_subnets.is_empty() {
            subscription_subnets.insert(0);
        }
        for &sid in aggregate_subnet_ids {
            subscription_subnets.insert(sid);
        }
    }

    // Subscribe to each resolved attestation subnet.
    // Non-validator/non-aggregator nodes end up with an empty set → no attestation topics.
    let mut sorted_subnets: Vec<u64> = subscription_subnets.into_iter().collect();
    sorted_subnets.sort_unstable();
    for subnet_id in sorted_subnets {
        topics.push(GossipsubTopic {
            fork: fork.clone(),
            kind: GossipsubKind::AttestationSubnet(subnet_id),
        });
    }

    topics
}

impl GossipsubTopic {
    pub fn decode(topic: &TopicHash) -> Result<Self, String> {
        let topic_parts = Self::split_topic(topic)?;
        Self::validate_parts(&topic_parts, topic)?;
        let fork = Self::extract_fork(&topic_parts);
        let kind = Self::extract_kind(&topic_parts)?;

        Ok(GossipsubTopic { fork, kind })
    }

    fn split_topic(topic: &TopicHash) -> Result<Vec<&str>, String> {
        let parts: Vec<&str> = topic.as_str().trim_start_matches('/').split('/').collect();

        if parts.len() != 4 {
            return Err(format!("Invalid topic part count: {topic:?}"));
        }

        Ok(parts)
    }

    fn validate_parts(parts: &[&str], topic: &TopicHash) -> Result<(), String> {
        if parts[0] != TOPIC_PREFIX || parts[3] != SSZ_SNAPPY_ENCODING_POSTFIX {
            return Err(format!("Invalid topic parts: {topic:?}"));
        }
        Ok(())
    }

    fn extract_fork(parts: &[&str]) -> String {
        parts[1].to_string()
    }

    fn extract_kind(parts: &[&str]) -> Result<GossipsubKind, String> {
        let topic_name = parts[2];

        if topic_name == BLOCK_TOPIC {
            Ok(GossipsubKind::Block)
        } else if topic_name == AGGREGATION_TOPIC {
            Ok(GossipsubKind::Aggregation)
        } else if let Some(subnet_str) = topic_name.strip_prefix(ATTESTATION_SUBNET_PREFIX) {
            let subnet_id = subnet_str.parse::<u64>().map_err(|e| {
                format!("Invalid attestation subnet id: {subnet_str:?}, error: {e}")
            })?;
            Ok(GossipsubKind::AttestationSubnet(subnet_id))
        } else {
            Err(format!("Invalid topic kind: {topic_name:?}"))
        }
    }
}

impl std::fmt::Display for GossipsubTopic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "/{}/{}/{}/{}",
            TOPIC_PREFIX, self.fork, self.kind, SSZ_SNAPPY_ENCODING_POSTFIX
        )
    }
}

impl From<GossipsubTopic> for IdentTopic {
    fn from(topic: GossipsubTopic) -> IdentTopic {
        IdentTopic::new(topic)
    }
}

impl From<GossipsubTopic> for String {
    fn from(topic: GossipsubTopic) -> Self {
        topic.to_string()
    }
}

impl From<GossipsubTopic> for TopicHash {
    fn from(val: GossipsubTopic) -> Self {
        let kind_str = match &val.kind {
            GossipsubKind::Block => BLOCK_TOPIC.to_string(),
            GossipsubKind::AttestationSubnet(subnet_id) => {
                format!("{ATTESTATION_SUBNET_PREFIX}{subnet_id}")
            }
            GossipsubKind::Aggregation => AGGREGATION_TOPIC.to_string(),
        };
        TopicHash::from_raw(format!(
            "/{}/{}/{}/{}",
            TOPIC_PREFIX, val.fork, kind_str, SSZ_SNAPPY_ENCODING_POSTFIX
        ))
    }
}

impl std::fmt::Display for GossipsubKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GossipsubKind::Block => write!(f, "{BLOCK_TOPIC}"),
            GossipsubKind::AttestationSubnet(subnet_id) => {
                write!(f, "{ATTESTATION_SUBNET_PREFIX}{subnet_id}")
            }
            GossipsubKind::Aggregation => write!(f, "{AGGREGATION_TOPIC}"),
        }
    }
}
