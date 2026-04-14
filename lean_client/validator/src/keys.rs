use ssz::H256;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::info;

use anyhow::anyhow;
use anyhow::{Context, Result, ensure};
use xmss::{SecretKey, Signature};

/// Manages XMSS secret keys for validators (attestation + proposal keys per validator)
pub struct KeyManager {
    /// Map of validator index to attestation secret key
    attestation_keys: HashMap<u64, SecretKey>,
    /// Map of validator index to proposal secret key
    proposal_keys: HashMap<u64, SecretKey>,
    /// Path to keys directory
    keys_dir: PathBuf,
}

impl KeyManager {
    /// Load keys from the hash-sig-keys directory
    pub fn new(keys_dir: impl AsRef<Path>) -> Result<Self> {
        let keys_dir = keys_dir.as_ref().to_path_buf();

        ensure!(keys_dir.exists(), "Keys directory not found: {keys_dir:?}");

        info!(path = ?keys_dir, "Initializing key manager");

        Ok(KeyManager {
            attestation_keys: HashMap::new(),
            proposal_keys: HashMap::new(),
            keys_dir,
        })
    }

    /// Load both attestation and proposal keys for a specific validator index.
    ///
    /// Expects files named:
    ///   `validator_{idx}_attestation_sk.ssz` — attestation signing key
    ///   `validator_{idx}_proposal_sk.ssz`    — block proposal signing key
    pub fn load_keys(&mut self, validator_index: u64) -> Result<()> {
        let attest_path = self
            .keys_dir
            .join(format!("validator_{validator_index}_attestation_sk.ssz"));
        let proposal_path = self
            .keys_dir
            .join(format!("validator_{validator_index}_proposal_sk.ssz"));

        // todo(security): this probably should be zeroized
        let attest_bytes = std::fs::read(&attest_path).context(format!(
            "Failed to read attestation key file: {attest_path:?}"
        ))?;
        let attest_key = SecretKey::try_from(attest_bytes.as_slice())?;

        let proposal_bytes = std::fs::read(&proposal_path).context(format!(
            "Failed to read proposal key file: {proposal_path:?}"
        ))?;
        let proposal_key = SecretKey::try_from(proposal_bytes.as_slice())?;

        info!(
            validator = validator_index,
            attest_size = attest_bytes.len(),
            proposal_size = proposal_bytes.len(),
            "Loaded attestation and proposal keys"
        );

        self.attestation_keys.insert(validator_index, attest_key);
        self.proposal_keys.insert(validator_index, proposal_key);
        Ok(())
    }

    /// Load attestation and proposal keys from explicit file paths.
    /// Used when annotated_validators.yaml provides the filenames directly.
    pub fn load_keys_from_files(
        &mut self,
        validator_index: u64,
        attest_path: &std::path::Path,
        proposal_path: &std::path::Path,
    ) -> Result<()> {
        let attest_bytes = std::fs::read(attest_path).context(format!(
            "Failed to read attestation key file: {attest_path:?}"
        ))?;
        let attest_key = SecretKey::try_from(attest_bytes.as_slice())?;

        let proposal_bytes = std::fs::read(proposal_path).context(format!(
            "Failed to read proposal key file: {proposal_path:?}"
        ))?;
        let proposal_key = SecretKey::try_from(proposal_bytes.as_slice())?;

        info!(
            validator = validator_index,
            attest_size = attest_bytes.len(),
            proposal_size = proposal_bytes.len(),
            "Loaded attestation and proposal keys"
        );

        self.attestation_keys.insert(validator_index, attest_key);
        self.proposal_keys.insert(validator_index, proposal_key);
        Ok(())
    }

    /// Sign an attestation message with the validator's attestation secret key.
    pub fn sign_attestation(
        &self,
        validator_index: u64,
        epoch: u32,
        message: H256,
    ) -> Result<Signature> {
        let key = self.attestation_keys.get(&validator_index).ok_or_else(|| {
            anyhow!(
                "No attestation key loaded for validator {}",
                validator_index
            )
        })?;

        key.sign(message, epoch)
    }

    /// Sign a block with the validator's proposal secret key.
    pub fn sign_proposal(
        &self,
        validator_index: u64,
        epoch: u32,
        message: H256,
    ) -> Result<Signature> {
        let key = self
            .proposal_keys
            .get(&validator_index)
            .ok_or_else(|| anyhow!("No proposal key loaded for validator {}", validator_index))?;

        key.sign(message, epoch)
    }

    /// Check if both attestation and proposal keys are loaded for a validator.
    pub fn has_key(&self, validator_index: u64) -> bool {
        self.attestation_keys.contains_key(&validator_index)
            && self.proposal_keys.contains_key(&validator_index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_manager_creation() {
        // This will fail if directory doesn't exist, which is expected
        let result = KeyManager::new("/nonexistent/path");
        assert!(result.is_err());
    }
}
