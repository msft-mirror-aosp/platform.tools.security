//! This module describes the public key (PubKeyEd25519 or PubKeyECDSA256)
//! used in the BccPayload. The key itself is stored as a simple byte array in
//! a vector.

use crate::bcc::get_label_value_as_bytes;
use crate::display::write_bytes_in_hex;
use anyhow::{bail, ensure, Context, Result};
use coset::{iana, Algorithm, CoseKey};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey};
use openssl::sign::Verifier;
use std::fmt::{self, Display, Formatter};

/// Length of an Ed25519 public key.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// Length of an Ed25519 signatures.
pub const ED25519_SIG_LEN: usize = 64;
/// Length of a P256 coordinate.
pub const P256_COORD_LEN: usize = 32;
/// Length of a P256 signature.
pub const P256_SIG_LEN: usize = 64;

enum PubKey {
    Ed25519 { pub_key: [u8; ED25519_PUBLIC_KEY_LEN] },
    P256 { x_coord: [u8; P256_COORD_LEN], y_coord: [u8; P256_COORD_LEN] },
}
/// Struct wrapping the public key byte array, and the relevant validation methods.
pub struct PublicKey {
    key: PubKey,
}

impl PublicKey {
    /// Extract the PublicKey from Subject Public Key.
    /// (CertificateRequest.BccEntry.payload[SubjectPublicKey].X)
    pub fn from_cose_key(pkey: &CoseKey) -> Result<Self> {
        let x = get_label_value_as_bytes(pkey, iana::OkpKeyParameter::X as i64)?;
        match pkey.alg {
            Some(coset::Algorithm::Assigned(iana::Algorithm::EdDSA)) => {
                PublicKey::new(PubKey::Ed25519 {
                    pub_key: x.as_slice().try_into().context(format!(
                        "Failed to convert x_coord to array. Len: {:?}",
                        x.len()
                    ))?,
                })
            }
            Some(coset::Algorithm::Assigned(iana::Algorithm::ES256)) => {
                let y = get_label_value_as_bytes(pkey, iana::Ec2KeyParameter::Y as i64)?;
                PublicKey::new(PubKey::P256 {
                    x_coord: x.as_slice().try_into().context(format!(
                        "Failed to convert x_coord to array. Len: {:?}",
                        x.len()
                    ))?,
                    y_coord: y.as_slice().try_into().context(format!(
                        "Failed to convert y_coord to array. Len: {:?}",
                        y.len()
                    ))?,
                })
            }
            _ => bail!("Unsupported signature algorithm: {:?}", pkey.alg),
        }
    }

    fn new(key: PubKey) -> Result<Self> {
        Ok(Self { key })
    }

    fn verify_ed25519(
        pub_key: &[u8; ED25519_PUBLIC_KEY_LEN],
        signature: &[u8],
        message: &[u8],
    ) -> Result<bool> {
        ensure!(
            signature.len() == ED25519_SIG_LEN,
            "Unexpected signature length: {:?}",
            signature.len()
        );
        let pkey = PKey::public_key_from_raw_bytes(pub_key, Id::ED25519)
            .context("Failed to create PKey")?;
        let mut verifier =
            Verifier::new_without_digest(&pkey).context("Failed to create verifier")?;
        verifier.verify_oneshot(signature, message).context("Failed to verify signature")
    }

    fn verify_p256(
        x_coord: &[u8; P256_COORD_LEN],
        y_coord: &[u8; P256_COORD_LEN],
        signature: &[u8],
        message: &[u8],
    ) -> Result<bool> {
        ensure!(
            signature.len() == P256_SIG_LEN,
            "Unexpected signature length: {:?}",
            signature.len()
        );
        // Construct an X9.62 uncompressed point from the coords.
        let mut point_uncompressed = [0; 1 + P256_COORD_LEN + P256_COORD_LEN];
        point_uncompressed[0] = 0x04;
        point_uncompressed[1..1 + P256_COORD_LEN].copy_from_slice(x_coord);
        point_uncompressed[1 + P256_COORD_LEN..].copy_from_slice(y_coord);
        // Initialize a key based on the point.
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
            .context("Failed to construct X9_62_prime256v1 group")?;
        let mut ctx = BigNumContext::new().context("Failed to allocate BigNumContext")?;
        let point = EcPoint::from_bytes(&group, &point_uncompressed, &mut ctx)
            .context("Failed to create EC point")?;
        let key =
            EcKey::from_public_key(&group, &point).context("Failed to create EC public key")?;
        let pkey = PKey::from_ec_key(key).context("Failed to create PKey")?;
        // Convert the signature from raw to DER format.
        let (r, s) = signature.split_at(P256_COORD_LEN);
        let r = BigNum::from_slice(r).context("Failed to create BigNum for r")?;
        let s = BigNum::from_slice(s).context("Failed to create BigNum for s")?;
        let signature =
            EcdsaSig::from_private_components(r, s).context("Failed to create ECDSA signature")?;
        let signature = signature.to_der().context("Failed to DER encode signature")?;
        // Verify the signature against the message.
        let mut verifier =
            Verifier::new(MessageDigest::sha256(), &pkey).context("Failed to create verifier")?;
        verifier.verify_oneshot(&signature, message).context("Failed to verify signature")
    }

    /// Verify that the signature obtained from signing the given message
    /// with the PublicKey matches the signature provided.
    pub fn verify(&self, signature: &[u8], message: &[u8], alg: &Option<Algorithm>) -> Result<()> {
        match &self.key {
            PubKey::Ed25519 { pub_key } => {
                ensure!(
                    *alg == Some(coset::Algorithm::Assigned(iana::Algorithm::EdDSA)),
                    "Unexpected algorithm. Ed25519 key, but alg is: {:?}",
                    *alg
                );
                ensure!(
                    Self::verify_ed25519(pub_key, signature, message)?,
                    "Signature verification failed."
                );
            }
            PubKey::P256 { x_coord, y_coord } => {
                ensure!(
                    *alg == Some(coset::Algorithm::Assigned(iana::Algorithm::ES256)),
                    "Unexpected algorithm. P256 key, but alg is: {:?}",
                    *alg
                );
                ensure!(
                    Self::verify_p256(x_coord, y_coord, signature, message)?,
                    "Signature verification failed."
                );
            }
        }
        Ok(())
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        match self.key {
            PubKey::Ed25519 { pub_key } => {
                f.write_str("Ed25519 X: ")?;
                write_bytes_in_hex(f, &pub_key)?;
            }
            PubKey::P256 { x_coord, y_coord } => {
                f.write_str("P256 X: ")?;
                write_bytes_in_hex(f, &x_coord)?;
                f.write_str(" Y: ")?;
                write_bytes_in_hex(f, &y_coord)?;
            }
        }
        Ok(())
    }
}
