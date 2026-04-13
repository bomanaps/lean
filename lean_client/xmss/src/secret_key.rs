use anyhow::{Error, Result, anyhow};
use derive_more::Debug;
use leansig::serialization::Serializable;
use leansig::signature::SignatureScheme;
use leansig::signature::generalized_xmss::instantiations_aborting::lifetime_2_to_the_32::{
    SchemeAbortingTargetSumLifetime32Dim46Base8 as XmssScheme,
    SecretKeyAbortingTargetSumLifetime32Dim46Base8 as XmssSecretKey,
};
use rand::CryptoRng;
use ssz::H256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{PublicKey, Signature};

#[derive(Clone, Zeroize, ZeroizeOnDrop, Debug)]
#[debug("[REDACTED]")]
pub struct SecretKey(Vec<u8>);

impl SecretKey {
    pub fn sign(&self, message: H256, epoch: u32) -> Result<Signature> {
        let sk = XmssSecretKey::from_bytes(&self.0)
            .map_err(|_| anyhow!("failed to deserialize secret key"))?;
        let sig = XmssScheme::sign(&sk, epoch, message.as_fixed_bytes())
            .map_err(|_| anyhow!("failed to sign message"))?;
        Ok(Signature::from_lean(sig))
    }

    pub fn generate_key_pair<R: CryptoRng>(
        rng: &mut R,
        activation_epoch: u32,
        num_active_epochs: u32,
    ) -> (PublicKey, SecretKey) {
        let (pk, sk) =
            XmssScheme::key_gen(rng, activation_epoch as usize, num_active_epochs as usize);
        (PublicKey::from_lean(pk), SecretKey(sk.to_bytes()))
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        XmssSecretKey::from_bytes(value)
            .map_err(|_| anyhow!("value is not valid secret key"))?;
        Ok(Self(value.to_vec()))
    }
}
