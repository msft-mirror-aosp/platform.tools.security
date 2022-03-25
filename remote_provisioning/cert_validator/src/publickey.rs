//! This module describes the public key (PubKeyEd25519 or PubKeyECDSA256)
//! used in the BccPayload. The key itself is stored as a simple byte array in
//! a vector. For now, only PubKeyEd25519 types of cbor public keys are supported.

use anyhow::{anyhow, ensure, Result};
use coset::{iana, Algorithm, CoseKey};

/// Public key length.
pub const PUBLIC_KEY_LEN: usize = ssl_bindgen::ED25519_PUBLIC_KEY_LEN as usize;
/// Signature length.
pub const SIGNATURE_LEN: usize = ssl_bindgen::ED25519_SIGNATURE_LEN as usize;

/// Struct wrapping the public key byte array, and the relevant validation methods.
pub struct PublicKey([u8; PUBLIC_KEY_LEN]);

impl PublicKey {
    /// Extract the PublicKey from Subject Public Key.
    /// (CertificateRequest.BccEntry.payload[SubjectPublicKey].X)
    pub fn from_cose_key(pkey: &CoseKey) -> Result<Self> {
        let x = pkey
            .params
            .iter()
            .find(|(k, _)| k == &coset::Label::Int(iana::OkpKeyParameter::X as i64))
            .ok_or_else(|| anyhow!("X not found"))?
            .1
            .as_bytes()
            .ok_or_else(|| anyhow!("X not bytes"))?;

        PublicKey::new(x)
    }

    fn new(public_key: &[u8]) -> Result<Self> {
        Ok(Self(public_key.try_into()?))
    }

    /// Verify that the signature obtained from signing the given message
    /// with the PublicKey matches the signature provided.
    pub fn verify(&self, signature: &[u8], message: &[u8], alg: &Option<Algorithm>) -> Result<()> {
        ensure!(signature.len() == SIGNATURE_LEN);
        // TODO: add match(alg) and handle the case for ECDSA.
        ensure!(*alg == Some(coset::Algorithm::Assigned(iana::Algorithm::EdDSA)));
        ensure!(
            unsafe {
                ssl_bindgen::ED25519_verify(
                    message.as_ptr(),
                    message.len().try_into()?,
                    signature.as_ptr(),
                    self.0.as_ptr(),
                )
            } == 1
        );
        Ok(())
    }
}
