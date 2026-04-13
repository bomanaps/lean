use core::fmt::{self, Display};
use std::{str::FromStr, sync::Once};

use crate::{PublicKey, Signature};
use anyhow::{Context, Error, Result, anyhow, bail};
use ethereum_types::H256;
use rec_aggregation::{AggregatedXMSS, init_aggregation_bytecode, xmss_aggregate, xmss_verify_aggregation};
use metrics::{METRICS, stop_and_discard};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use ssz::{ByteList, ReadError, Size, SszHash, SszRead, SszSize, SszWrite, WriteError, U1};
use typenum::U1048576;

/// Max size currently is 1MiB by spec.
type AggregatedSignatureSizeLimit = U1048576;

/// Cryptographic proof that a set of validators signed a message.
///
/// Note: this doesn't follow spec a bit - in spec this would be a `proof_data`
///   field of AggregatedSignatureProof type. Implemented like this to have a
///   bit of nice encapsulation, so that xmss-related types don't leak
///   abstraction into containers crate.
///
/// SSZ traits are implemented manually (not derived) so that `SszRead` can validate
/// the inner bytes via `AggregatedXMSS::deserialize` at decode time, rejecting
/// malformed gossip messages at the boundary instead of panicking later in `as_lean`.
#[derive(Debug, Clone)]
pub struct AggregatedSignature(ByteList<AggregatedSignatureSizeLimit>);

impl SszSize for AggregatedSignature {
    const SIZE: Size = Size::Variable { minimum_size: 0 };
}

impl<C> SszRead<C> for AggregatedSignature {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        let inner =
            ByteList::<AggregatedSignatureSizeLimit>::from_ssz_unchecked(context, bytes)?;
        AggregatedXMSS::deserialize(inner.as_bytes()).ok_or(ReadError::Custom {
            message: "invalid aggregated XMSS signature",
        })?;
        Ok(Self(inner))
    }
}

impl SszWrite for AggregatedSignature {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        self.0.write_variable(bytes)
    }
}

impl SszHash for AggregatedSignature {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        self.0.hash_tree_root()
    }
}

fn setup_aggregation() {
    static SETUP: Once = Once::new();
    SETUP.call_once(init_aggregation_bytecode);
}

impl AggregatedSignature {
    pub fn new(bytes: &[u8]) -> Result<Self> {
        let bytes = ByteList::try_from(bytes.to_vec())
            .context("signature too large - currently max 1MiB signatures allowed")?;

        AggregatedXMSS::deserialize(bytes.as_bytes())
            .ok_or_else(|| anyhow!("invalid aggregated signature"))?;

        Ok(Self(bytes))
    }

    pub fn aggregate(
        public_keys: impl IntoIterator<Item = PublicKey>,
        signatures: impl IntoIterator<Item = Signature>,
        message: H256,
        slot: u32,
        log_inv_rate: usize,
    ) -> Result<Self> {
        Self::aggregate_with_children(&[], public_keys, signatures, message, slot, log_inv_rate)
    }

    /// Aggregate signatures with optional recursive child proofs.
    ///
    /// `children` is a list of `(public_keys_covered_by_child, child_proof)` pairs.
    /// Each child proof was previously produced by aggregating the listed public keys,
    /// allowing recursive / hierarchical proof compaction.
    pub fn aggregate_with_children(
        children: &[(&[PublicKey], &AggregatedSignature)],
        public_keys: impl IntoIterator<Item = PublicKey>,
        signatures: impl IntoIterator<Item = Signature>,
        message: H256,
        slot: u32,
        log_inv_rate: usize,
    ) -> Result<Self> {
        setup_aggregation();

        let timer = METRICS.get().map(|metrics| {
            metrics
                .lean_pq_sig_aggregated_signatures_building_time_seconds
                .start_timer()
        });

        let public_keys = public_keys.into_iter().collect::<Vec<_>>();
        let signatures = signatures.into_iter().collect::<Vec<_>>();

        if public_keys.len() != signatures.len() {
            stop_and_discard(timer);
            bail!(
                "public key & signature count mismatch ({} != {})",
                public_keys.len(),
                signatures.len()
            );
        }

        if public_keys.is_empty() && children.is_empty() {
            stop_and_discard(timer);
            bail!("cannot aggregate: no raw signatures and no children");
        }

        let sig_count = public_keys.len();

        let raw_xmss = public_keys
            .into_iter()
            .zip(signatures)
            .map(|(pk, sig)| (pk.as_lean(), sig.as_lean()))
            .collect::<Vec<_>>();

        // Convert children: store owned XmssPublicKey Vecs and owned AggregatedXMSS values,
        // then build the reference slice that xmss_aggregate expects.
        let lean_pks_vec: Vec<Vec<_>> = children
            .iter()
            .map(|(pks, _)| pks.iter().map(|pk| pk.as_lean()).collect())
            .collect();
        let lean_agg_vec: Vec<_> = children
            .iter()
            .map(|(_, agg)| agg.as_lean())
            .collect::<Result<Vec<_>>>()?;

        let children_arg: Vec<(&[_], _)> = lean_pks_vec
            .iter()
            .zip(lean_agg_vec.into_iter())
            .map(|(pks, agg)| (pks.as_slice(), agg))
            .collect();

        let (_pub_keys, agg) = xmss_aggregate(
            &children_arg,
            raw_xmss,
            message.as_fixed_bytes(),
            slot,
            log_inv_rate,
        );

        METRICS.get().map(|metrics| {
            metrics
                .lean_pq_sig_aggregated_signatures_total
                .inc_by(sig_count as u64)
        });

        let bytes = agg.serialize();
        Ok(Self(
            ByteList::try_from(bytes)
                .context("aggregated proof too large - exceeds 1MiB limit")?,
        ))
    }

    pub fn verify(
        &self,
        public_keys: impl IntoIterator<Item = PublicKey>,
        message: H256,
        slot: u32,
    ) -> Result<()> {
        setup_aggregation();

        let _timer = METRICS.get().map(|metrics| {
            metrics
                .lean_pq_sig_aggregated_signatures_verification_time_seconds
                .start_timer()
        });

        let pub_keys = public_keys
            .into_iter()
            .map(|k| k.as_lean())
            .collect::<Vec<_>>();

        let agg = self.as_lean()?;

        xmss_verify_aggregation(pub_keys, &agg, message.as_fixed_bytes(), slot)
            .map(|_| ())
            .map_err(|err| anyhow!("{err:?}"))
            .inspect(|_| {
                METRICS
                    .get()
                    .map(|metrics| metrics.lean_pq_sig_aggregated_signatures_valid_total.inc());
            })
            .inspect_err(|_| {
                METRICS.get().map(|metrics| {
                    metrics
                        .lean_pq_sig_aggregated_signatures_invalid_total
                        .inc()
                });
            })
    }

    fn as_lean(&self) -> Result<AggregatedXMSS> {
        AggregatedXMSS::deserialize(self.0.as_bytes())
            .ok_or_else(|| anyhow!("invalid aggregated XMSS signature"))
    }

    // todo(xmss): this is a function used only for testing. ideally, it should not exist
    pub fn is_empty(&self) -> bool {
        self.0.as_bytes().is_empty()
    }
}

impl Display for AggregatedSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0.as_bytes()))
    }
}

impl FromStr for AggregatedSignature {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = s.strip_prefix("0x").unwrap_or(s);

        let bytes = hex::decode(data)?;

        Self::new(&bytes).map_err(|err| anyhow!("{err:?}"))
    }
}

impl Serialize for AggregatedSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<'de> Deserialize<'de> for AggregatedSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct DataWrapper {
            data: String,
        }

        let value = DataWrapper::deserialize(deserializer)?;

        value.data.parse().map_err(de::Error::custom)
    }
}
