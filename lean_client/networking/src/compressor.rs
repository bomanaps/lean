use crate::gossipsub::topic::{GossipsubKind, GossipsubTopic};
use libp2p::gossipsub::{DataTransform, Message, RawMessage, TopicHash};
use metrics::METRICS;
use sha2::{Digest, Sha256};
use snap::raw::{Decoder, Encoder};
use tracing::info;

pub struct Compressor;

impl Compressor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Compressor {
    fn default() -> Self {
        Self::new()
    }
}
impl DataTransform for Compressor {
    fn inbound_transform(&self, raw_message: RawMessage) -> Result<Message, std::io::Error> {
        let mut decoder = Decoder::new();
        match decoder.decompress_vec(&raw_message.data) {
            Ok(data) => Ok(Message {
                topic: raw_message.topic,
                data,
                sequence_number: raw_message.sequence_number,
                source: raw_message.source,
            }),
            Err(e) => {
                let kind = match GossipsubTopic::decode(&raw_message.topic) {
                    Ok(t) => match t.kind {
                        GossipsubKind::Block => "block",
                        GossipsubKind::Aggregation => "aggregation",
                        GossipsubKind::AttestationSubnet(_) => "attestation",
                    },
                    Err(_) => "unknown",
                };
                METRICS.get().map(|m| {
                    m.lean_gossip_decompress_failures_total
                        .with_label_values(&[kind])
                        .inc();
                });
                Err(std::io::Error::other(e))
            }
        }
    }

    fn outbound_transform(
        &self,
        topic: &TopicHash,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, std::io::Error> {
        let mut encoder = Encoder::new();
        let raw_message = encoder.compress_vec(&data)?;

        let kind = match GossipsubTopic::decode(topic) {
            Ok(t) => match t.kind {
                GossipsubKind::Block => "block",
                GossipsubKind::Aggregation => "aggregation",
                GossipsubKind::AttestationSubnet(_) => "attestation",
            },
            Err(_) => "unknown",
        };

        let sha256_ssz = hex::encode(Sha256::digest(&data));
        let sha256_compressed = hex::encode(Sha256::digest(&raw_message));

        let snappy_self_decode_ok: String = match kind {
            "block" | "aggregation" => match Decoder::new().decompress_vec(&raw_message) {
                Ok(round_trip) => (round_trip == data).to_string(),
                Err(_) => "decode_error".to_string(),
            },
            _ => "skipped".to_string(),
        };

        info!(
            target: "snappy_publish",
            topic_kind = kind,
            sha256_ssz = %&sha256_ssz[..16],
            sha256_compressed = %&sha256_compressed[..16],
            ssz_len = data.len(),
            compressed_len = raw_message.len(),
            snappy_self_decode_ok = %snappy_self_decode_ok,
            git_sha = git_version::git_version!(args = ["--always", "--abbrev=8"], fallback = "unknown"),
            "snappy publish",
        );

        Ok(raw_message)
    }
}
