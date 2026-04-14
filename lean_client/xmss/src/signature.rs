use core::{
    convert::TryFrom,
    fmt::{self, Debug, Display},
    str::FromStr,
};

use crate::public_key::PublicKey;
use anyhow::{Error, Result, anyhow};
use eth_ssz::DecodeError;
use leansig_wrapper::{XmssSignature, xmss_signature_from_ssz, xmss_signature_to_ssz, xmss_verify};
use metrics::METRICS;
use serde::de;
use serde::{Deserialize, Serialize};
use ssz::{ByteVector, H256, Ssz};
use typenum::{Sum, U8, U32, U64, U128, U256, U2048};

// 2536 = 2048 + 256 + 128 + 64 + 32 + 8
type SignatureSize = Sum<Sum<Sum<Sum<Sum<U2048, U256>, U128>, U64>, U32>, U8>;

type LeanSigSignature = XmssSignature;

// todo(xmss): default implementation doesn't make sense here, and is needed only for tests
#[derive(Clone, Default, Ssz)]
#[ssz(transparent)]
pub struct Signature(ByteVector<SignatureSize>);

impl Signature {
    pub fn new(inner: &[u8]) -> Result<Self, DecodeError> {
        xmss_signature_from_ssz(inner)
            .map_err(|_| DecodeError::BytesInvalid("invalid xmss signature".to_string()))?;

        Ok(Self(inner.try_into().expect(
            "slice of length != 2536 shouldn't deserialize as valid leansig signature",
        )))
    }

    pub fn verify(&self, public_key: &PublicKey, epoch: u32, message: H256) -> Result<()> {
        match xmss_verify(
            &public_key.as_lean(),
            epoch,
            message.as_fixed_bytes(),
            &self.as_lean(),
        ) {
            Ok(()) => {
                METRICS.get().map(|metrics| {
                    metrics.lean_pq_sig_attestation_signatures_valid_total.inc();
                });
                Ok(())
            }
            Err(()) => {
                METRICS.get().map(|metrics| {
                    metrics
                        .lean_pq_sig_attestation_signatures_invalid_total
                        .inc();
                });
                Err(anyhow!("invalid signature"))
            }
        }
    }

    pub(crate) fn from_lean(signature: LeanSigSignature) -> Self {
        let bytes = xmss_signature_to_ssz(&signature);

        Self(
            bytes
                .as_slice()
                .try_into()
                .expect("slice of length != 2536 shouldn't deserialize as valid leansig signature"),
        )
    }

    pub(crate) fn as_lean(&self) -> LeanSigSignature {
        xmss_signature_from_ssz(self.0.as_bytes())
            .expect("signature internal representation must be valid leansig signature")
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0.as_bytes()))
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0.as_bytes()))
    }
}

impl FromStr for Signature {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = s.strip_prefix("0x").unwrap_or(s);

        let bytes = hex::decode(data)?;

        Self::new(&bytes).map_err(|err| anyhow!("{err:?}"))
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = DecodeError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct DataWrapper<T> {
            data: T,
        }

        #[derive(Deserialize)]
        struct XmssSignatureJson {
            path: XmssPath,
            rho: DataWrapper<Vec<u32>>,
            hashes: DataWrapper<Vec<DataWrapper<Vec<u32>>>>,
        }

        #[derive(Deserialize)]
        struct XmssPath {
            siblings: DataWrapper<Vec<DataWrapper<Vec<u32>>>>,
        }

        let xmss_sig = XmssSignatureJson::deserialize(deserializer)?;
        let mut rho_bytes = Vec::new();
        for val in &xmss_sig.rho.data {
            rho_bytes.extend_from_slice(&val.to_le_bytes());
        }
        let rho_len = rho_bytes.len(); // Should be 28 (7 * 4)

        // 2. Serialize Path/Siblings (Variable length)
        let mut path_bytes = Vec::new();
        // Prepend 4 bytes (containing 4) as an offset which would come with real SSZ serialization
        let inner_offset: u32 = 4;
        path_bytes.extend_from_slice(&inner_offset.to_le_bytes()); // [04 00 00 00]
        for sibling in &xmss_sig.path.siblings.data {
            for val in &sibling.data {
                path_bytes.extend_from_slice(&val.to_le_bytes());
            }
        }

        // 3. Serialize Hashes (Variable length)
        let mut hashes_bytes = Vec::new();
        for hash in &xmss_sig.hashes.data {
            for val in &hash.data {
                hashes_bytes.extend_from_slice(&val.to_le_bytes());
            }
        }

        // --- STEP 2: CALCULATE OFFSETS ---

        // The fixed part contains:
        // 1. Path Offset (4 bytes)
        // 2. Rho Data (rho_len bytes)
        // 3. Hashes Offset (4 bytes)
        let fixed_part_size = 4 + rho_len + 4;

        // Offset to 'path' starts immediately after the fixed part
        let offset_path = fixed_part_size as u32;

        // Offset to 'hashes' starts after 'path' data
        let offset_hashes = offset_path + (path_bytes.len() as u32);

        // --- STEP 3: CONSTRUCT FINAL SSZ BYTES ---

        let mut ssz_bytes = Vec::new();

        // 1. Write Offset to Path (u32, Little Endian)
        ssz_bytes.extend_from_slice(&offset_path.to_le_bytes());

        // 2. Write Rho Data (Fixed)
        ssz_bytes.extend_from_slice(&rho_bytes);

        // 3. Write Offset to Hashes (u32, Little Endian)
        ssz_bytes.extend_from_slice(&offset_hashes.to_le_bytes());

        // 4. Write Path Data (Variable)
        ssz_bytes.extend_from_slice(&path_bytes);

        // 5. Write Hashes Data (Variable)
        ssz_bytes.extend_from_slice(&hashes_bytes);

        Signature::try_from(ssz_bytes.as_slice())
            .map_err(|err| de::Error::custom(format!("invalid signature: {err:?}")))
    }
}

#[cfg(test)]
mod test {
    use crate::signature::SignatureSize;
    use typenum::Unsigned;

    #[test]
    fn valid_signature_size() {
        assert_eq!(SignatureSize::U64, 2536);
    }
}
