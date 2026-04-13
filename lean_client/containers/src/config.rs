use serde::{Deserialize, Serialize};
use ssz::Ssz;
use std::{fs::File, io::BufReader, path::Path};

fn default_log_inv_rate() -> u8 {
    2
}

fn default_attestation_committee_count() -> u64 {
    1
}

#[derive(Clone, Debug, PartialEq, Eq, Ssz, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub genesis_time: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisValidatorEntry {
    pub attestation_pubkey: String,
    pub proposal_pubkey: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct GenesisConfig {
    pub genesis_time: u64,
    #[serde(default)]
    pub active_epoch: u64,
    #[serde(default)]
    pub validator_count: u64,
    pub genesis_validators: Vec<GenesisValidatorEntry>,
    #[serde(default = "default_log_inv_rate")]
    pub log_inv_rate: u8,
    #[serde(default = "default_attestation_committee_count")]
    pub attestation_committee_count: u64,
}

impl GenesisConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let config = serde_yaml::from_reader(reader)?;
        Ok(config)
    }
}
