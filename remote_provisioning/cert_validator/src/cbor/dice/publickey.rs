//! CBOR encoding and decoding of a [`PublicKey`].

use crate::publickey::{EcKind, Kind, PublicKey};
use anyhow::{anyhow, bail, ensure, Context, Result};
use coset::cbor::value::Value;
use coset::iana::{self, EnumI64};
use coset::{Algorithm, CoseKey, KeyOperation, KeyType, Label};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Public};

impl PublicKey {
    pub(super) fn from_cose_key(cose_key: &CoseKey) -> Result<Self> {
        if !cose_key.key_ops.is_empty() {
            ensure!(cose_key.key_ops.contains(&KeyOperation::Assigned(iana::KeyOperation::Verify)));
        }
        let pkey = match cose_key.kty {
            KeyType::Assigned(iana::KeyType::OKP) => pkey_from_okp_key(cose_key)?,
            KeyType::Assigned(iana::KeyType::EC2) => pkey_from_ec2_key(cose_key)?,
            _ => bail!("Unexpected KeyType value: {:?}", cose_key.kty),
        };
        pkey.try_into().context("Making PublicKey from PKey")
    }

    pub(super) fn iana_algorithm(&self) -> iana::Algorithm {
        match self.kind() {
            Kind::Ed25519 => iana::Algorithm::EdDSA,
            Kind::Ec(EcKind::P256) => iana::Algorithm::ES256,
            Kind::Ec(EcKind::P384) => iana::Algorithm::ES384,
        }
    }
}

fn pkey_from_okp_key(cose_key: &CoseKey) -> Result<PKey<Public>> {
    ensure!(cose_key.kty == KeyType::Assigned(iana::KeyType::OKP));
    ensure!(cose_key.alg == Some(Algorithm::Assigned(iana::Algorithm::EdDSA)));
    let crv = get_label_value(cose_key, Label::Int(iana::OkpKeyParameter::Crv.to_i64()))?;
    let x = get_label_value_as_bytes(cose_key, Label::Int(iana::OkpKeyParameter::X.to_i64()))?;
    ensure!(crv == &Value::from(iana::EllipticCurve::Ed25519.to_i64()));
    PKey::public_key_from_raw_bytes(x, Id::ED25519).context("Failed to instantiate key")
}

fn pkey_from_ec2_key(cose_key: &CoseKey) -> Result<PKey<Public>> {
    ensure!(cose_key.kty == KeyType::Assigned(iana::KeyType::EC2));
    let crv = get_label_value(cose_key, Label::Int(iana::Ec2KeyParameter::Crv.to_i64()))?;
    let x = get_label_value_as_bytes(cose_key, Label::Int(iana::Ec2KeyParameter::X.to_i64()))?;
    let y = get_label_value_as_bytes(cose_key, Label::Int(iana::Ec2KeyParameter::Y.to_i64()))?;
    match cose_key.alg {
        Some(Algorithm::Assigned(iana::Algorithm::ES256)) => {
            ensure!(crv == &Value::from(iana::EllipticCurve::P_256.to_i64()));
            pkey_from_ec_coords(Nid::X9_62_PRIME256V1, x, y).context("Failed to instantiate key")
        }
        Some(Algorithm::Assigned(iana::Algorithm::ES384)) => {
            ensure!(crv == &Value::from(iana::EllipticCurve::P_384.to_i64()));
            pkey_from_ec_coords(Nid::SECP384R1, x, y).context("Failed to instantiate key")
        }
        _ => bail!("Need to specify ES256 or ES384 in the key. Got {:?}", cose_key.alg),
    }
}

fn pkey_from_ec_coords(nid: Nid, x: &[u8], y: &[u8]) -> Result<PKey<Public>> {
    let group = EcGroup::from_curve_name(nid).context("Failed to construct curve group")?;
    let x = BigNum::from_slice(x).context("Failed to create x coord")?;
    let y = BigNum::from_slice(y).context("Failed to create y coord")?;
    let key = EcKey::from_public_key_affine_coordinates(&group, &x, &y)
        .context("Failed to create EC public key")?;
    PKey::from_ec_key(key).context("Failed to create PKey")
}

/// Get the value corresponding to the provided label within the supplied CoseKey or error if it's
/// not present.
fn get_label_value(key: &CoseKey, label: Label) -> Result<&Value> {
    Ok(&key
        .params
        .iter()
        .find(|(k, _)| k == &label)
        .ok_or_else(|| anyhow!("Label {:?} not found", label))?
        .1)
}

/// Get the byte string for the corresponding label within the key if the label exists and the
/// value is actually a byte array.
fn get_label_value_as_bytes(key: &CoseKey, label: Label) -> Result<&[u8]> {
    get_label_value(key, label)?
        .as_bytes()
        .ok_or_else(|| anyhow!("Value not a bstr."))
        .map(Vec::as_slice)
}
