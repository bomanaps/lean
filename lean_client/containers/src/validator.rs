use ssz::{PersistentList, Ssz};
use typenum::U4096;
use xmss::PublicKey;

// todo(containers): default implementation doesn't make sense here
#[derive(Clone, Debug, Ssz, Default)]
pub struct Validator {
    pub attestation_pubkey: PublicKey,
    pub proposal_pubkey: PublicKey,
    pub index: u64,
}

pub type ValidatorRegistryLimit = U4096;

pub type Validators = PersistentList<Validator, ValidatorRegistryLimit>;
