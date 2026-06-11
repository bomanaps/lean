use anyhow::{Error, Result, anyhow};
use derive_more::Debug;
use leansig::serialization::Serializable;
use leansig::signature::SignatureScheme;
use leansig::signature::generalized_xmss::instantiations_aborting::lifetime_2_to_the_32::{
    SIGAbortingTargetSumLifetime32Dim46Base8 as XmssScheme,
    SecretKeyAbortingTargetSumLifetime32Dim46Base8 as XmssSecretKey,
};
use rand::CryptoRng;
use ssz::H256;

use crate::{PublicKey, Signature};

// TODO(zeroize): upstream `XmssSecretKey` does not derive `Zeroize`, so we cannot
// derive `ZeroizeOnDrop` on the wrapper. Acceptable for devnet bring-up; before
// mainnet, either upstream a `Zeroize` derive on `GeneralizedXMSSSecretKey` or
// implement `Drop` here manually (zeroize the inner buffers via accessor).
#[derive(Debug)]
#[debug("[REDACTED]")]
pub struct SecretKey(XmssSecretKey);

impl SecretKey {
    pub fn sign(&self, message: H256, epoch: u32) -> Result<Signature> {
        let sig = XmssScheme::sign(&self.0, epoch, message.as_fixed_bytes())
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
        (PublicKey::from_lean(pk), SecretKey(sk))
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let sk = XmssSecretKey::from_bytes(value)
            .map_err(|_| anyhow!("value is not valid secret key"))?;
        Ok(Self(sk))
    }
}
