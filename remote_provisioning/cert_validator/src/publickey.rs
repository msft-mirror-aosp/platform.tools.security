//! This module describes the public key (PubKeyEd25519, PubKeyECDSA256 or
//! PubKeyECDSA384) used in the BccPayload. The key itself is stored as a
//! simple byte array in a vector.

use crate::bcc::{get_label_value, get_label_value_as_bytes};
use crate::display::write_bytes_in_hex;
use anyhow::{bail, ensure, Context, Result};
use coset::cbor::value::Value;
use coset::{iana, Algorithm, CoseKey};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Public};
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
/// Length of a P384 coordinate.
pub const P384_COORD_LEN: usize = 48;
/// Length of a P384 signature.
pub const P384_SIG_LEN: usize = 96;

/// Enumeration of the elliptic curve algorithms that are supported.
enum SupportedEc {
    P256,
    P384,
}

enum PubKey {
    Ed25519 { pub_key: [u8; ED25519_PUBLIC_KEY_LEN] },
    P256 { x_coord: [u8; P256_COORD_LEN], y_coord: [u8; P256_COORD_LEN] },
    P384 { x_coord: [u8; P384_COORD_LEN], y_coord: [u8; P384_COORD_LEN] },
}

/// Struct wrapping the public key and relevant validation methods.
pub struct PublicKey {
    key: PubKey,
    pkey: PKey<Public>,
}

impl PublicKey {
    pub(super) fn from_cose_key(pkey: &CoseKey) -> Result<Self> {
        if !pkey.key_ops.is_empty() {
            ensure!(pkey
                .key_ops
                .contains(&coset::KeyOperation::Assigned(iana::KeyOperation::Verify)));
        }
        match pkey.kty {
            coset::KeyType::Assigned(iana::KeyType::OKP) => Self::from_cose_okp_key(pkey),
            coset::KeyType::Assigned(iana::KeyType::EC2) => Self::from_cose_ec2_key(pkey),
            _ => bail!("Unexpected KeyType value: {:?}", pkey.kty),
        }
    }

    fn from_cose_okp_key(pkey: &CoseKey) -> Result<Self> {
        ensure!(pkey.kty == coset::KeyType::Assigned(iana::KeyType::OKP));
        ensure!(pkey.alg == Some(coset::Algorithm::Assigned(iana::Algorithm::EdDSA)));
        let crv = get_label_value(pkey, iana::OkpKeyParameter::Crv as i64)?;
        let x = get_label_value_as_bytes(pkey, iana::OkpKeyParameter::X as i64)?;
        ensure!(crv == &Value::from(iana::EllipticCurve::Ed25519 as i64));
        let key = PubKey::Ed25519 {
            pub_key: x
                .as_slice()
                .try_into()
                .context(format!("Failed to convert x_coord to array. Len: {:?}", x.len()))?,
        };
        let pkey =
            PKey::public_key_from_raw_bytes(x, Id::ED25519).context("Failed to instantiate key")?;
        Ok(Self { key, pkey })
    }

    fn from_cose_ec2_key(pkey: &CoseKey) -> Result<Self> {
        ensure!(pkey.kty == coset::KeyType::Assigned(iana::KeyType::EC2));
        let crv = get_label_value(pkey, iana::Ec2KeyParameter::Crv as i64)?;
        let x = get_label_value_as_bytes(pkey, iana::Ec2KeyParameter::X as i64)?;
        let y = get_label_value_as_bytes(pkey, iana::Ec2KeyParameter::Y as i64)?;
        match pkey.alg {
            Some(coset::Algorithm::Assigned(iana::Algorithm::ES256)) => {
                ensure!(crv == &Value::from(iana::EllipticCurve::P_256 as i64));
                let key = PubKey::P256 {
                    x_coord: x.as_slice().try_into().context(format!(
                        "Failed to convert x_coord to array. Len: {:?}",
                        x.len()
                    ))?,
                    y_coord: y.as_slice().try_into().context(format!(
                        "Failed to convert y_coord to array. Len: {:?}",
                        y.len()
                    ))?,
                };
                let pkey = Self::ec_pkey_from_bytes(SupportedEc::P256, x, y)
                    .context("Failed to instantiate key")?;
                Ok(Self { key, pkey })
            }
            Some(coset::Algorithm::Assigned(iana::Algorithm::ES384)) => {
                ensure!(crv == &Value::from(iana::EllipticCurve::P_384 as i64));
                let key = PubKey::P384 {
                    x_coord: x.as_slice().try_into().context(format!(
                        "Failed to convert x_coord to array. Len: {:?}",
                        x.len()
                    ))?,
                    y_coord: y.as_slice().try_into().context(format!(
                        "Failed to convert y_coord to array. Len: {:?}",
                        y.len()
                    ))?,
                };
                let pkey = Self::ec_pkey_from_bytes(SupportedEc::P384, x, y)
                    .context("Failed to instantiate key")?;
                Ok(Self { key, pkey })
            }
            _ => bail!("Need to specify ES256 or ES384 in the key. Got {:?}", pkey.alg),
        }
    }

    fn ec_pkey_from_bytes(
        curve: SupportedEc,
        x_coord: &[u8],
        y_coord: &[u8],
    ) -> Result<PKey<Public>> {
        let (nid, coord_len) = match curve {
            SupportedEc::P256 => (Nid::X9_62_PRIME256V1, P256_COORD_LEN),
            SupportedEc::P384 => (Nid::SECP384R1, P384_COORD_LEN),
        };
        // Construct an X9.62 uncompressed point from the coords.
        let mut point_uncompressed = vec![0; 1 + coord_len + coord_len];
        point_uncompressed[0] = 0x04;
        point_uncompressed[1..1 + coord_len].copy_from_slice(x_coord);
        point_uncompressed[1 + coord_len..].copy_from_slice(y_coord);
        // Initialize a key based on the point.
        let group = EcGroup::from_curve_name(nid).context("Failed to construct curve group")?;
        let mut ctx = BigNumContext::new().context("Failed to allocate BigNumContext")?;
        let point = EcPoint::from_bytes(&group, &point_uncompressed, &mut ctx)
            .context("Failed to create EC point")?;
        let key =
            EcKey::from_public_key(&group, &point).context("Failed to create EC public key")?;
        PKey::from_ec_key(key).context("Failed to create PKey")
    }

    pub(super) fn algorithm(&self) -> Algorithm {
        match &self.key {
            PubKey::Ed25519 { .. } => Algorithm::Assigned(iana::Algorithm::EdDSA),
            PubKey::P256 { .. } => Algorithm::Assigned(iana::Algorithm::ES256),
            PubKey::P384 { .. } => Algorithm::Assigned(iana::Algorithm::ES384),
        }
    }

    fn verify_ed25519(&self, signature: &[u8], message: &[u8]) -> Result<bool> {
        ensure!(
            signature.len() == ED25519_SIG_LEN,
            "Unexpected signature length: {:?}",
            signature.len()
        );
        let mut verifier =
            Verifier::new_without_digest(&self.pkey).context("Failed to create verifier")?;
        verifier.verify_oneshot(signature, message).context("Failed to verify signature")
    }

    fn verify_ec(&self, curve: SupportedEc, signature: &[u8], message: &[u8]) -> Result<bool> {
        let (coord_len, sig_len, digest) = match curve {
            SupportedEc::P256 => (P256_COORD_LEN, P256_SIG_LEN, MessageDigest::sha256()),
            SupportedEc::P384 => (P384_COORD_LEN, P384_SIG_LEN, MessageDigest::sha384()),
        };
        ensure!(signature.len() == sig_len, "Unexpected signature length: {:?}", signature.len());
        // Convert the signature from raw to DER format.
        let (r, s) = signature.split_at(coord_len);
        let r = BigNum::from_slice(r).context("Failed to create BigNum for r")?;
        let s = BigNum::from_slice(s).context("Failed to create BigNum for s")?;
        let signature =
            EcdsaSig::from_private_components(r, s).context("Failed to create ECDSA signature")?;
        let signature = signature.to_der().context("Failed to DER encode signature")?;
        // Verify the signature against the message.
        let mut verifier =
            Verifier::new(digest, &self.pkey).context("Failed to create verifier")?;
        verifier.verify_oneshot(&signature, message).context("Failed to verify signature")
    }

    /// Verify that the signature obtained from signing the given message
    /// with the PublicKey matches the signature provided.
    pub fn verify(&self, signature: &[u8], message: &[u8]) -> Result<()> {
        let verified = match &self.key {
            PubKey::Ed25519 { .. } => self.verify_ed25519(signature, message)?,
            PubKey::P256 { .. } => self
                .verify_ec(SupportedEc::P256, signature, message)
                .context("Failed to verify p256 signature")?,
            PubKey::P384 { .. } => self
                .verify_ec(SupportedEc::P384, signature, message)
                .context("Failed to verify p384 signature")?,
        };
        ensure!(verified, "Signature verification failed.");
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
            PubKey::P384 { x_coord, y_coord } => {
                f.write_str("P384 X: ")?;
                write_bytes_in_hex(f, &x_coord)?;
                f.write_str(" Y: ")?;
                write_bytes_in_hex(f, &y_coord)?;
            }
        }
        Ok(())
    }
}
