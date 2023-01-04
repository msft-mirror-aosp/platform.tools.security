//! This module describes the public key (PubKeyEd25519, PubKeyECDSA256 or
//! PubKeyECDSA384) used in the BccPayload. The key itself is stored as a
//! simple byte array in a vector.

use anyhow::{anyhow, bail, ensure, Context, Result};
use coset::cbor::value::Value;
use coset::iana::{self, EnumI64};
use coset::{Algorithm, CoseKey, KeyOperation, KeyType, Label};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Public};
use openssl::sign::Verifier;
use std::error::Error;
use std::fmt;

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

/// Enumeration of the kinds of key that are supported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Ed25519,
    Ec(EcKind),
}

/// Enumeration of the kinds of elliptic curve keys that are supported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EcKind {
    P256,
    P384,
}

/// Struct wrapping the public key and relevant validation methods.
pub struct PublicKey {
    kind: Kind,
    pkey: PKey<Public>,
}

impl PublicKey {
    pub(super) fn from_cose_key(pkey: &CoseKey) -> Result<Self> {
        if !pkey.key_ops.is_empty() {
            ensure!(pkey.key_ops.contains(&KeyOperation::Assigned(iana::KeyOperation::Verify)));
        }
        match pkey.kty {
            KeyType::Assigned(iana::KeyType::OKP) => Self::from_cose_okp_key(pkey),
            KeyType::Assigned(iana::KeyType::EC2) => Self::from_cose_ec2_key(pkey),
            _ => bail!("Unexpected KeyType value: {:?}", pkey.kty),
        }
    }

    fn from_cose_okp_key(pkey: &CoseKey) -> Result<Self> {
        ensure!(pkey.kty == KeyType::Assigned(iana::KeyType::OKP));
        ensure!(pkey.alg == Some(Algorithm::Assigned(iana::Algorithm::EdDSA)));
        let crv = get_label_value(pkey, Label::Int(iana::OkpKeyParameter::Crv.to_i64()))?;
        let x = get_label_value_as_bytes(pkey, Label::Int(iana::OkpKeyParameter::X.to_i64()))?;
        ensure!(crv == &Value::from(iana::EllipticCurve::Ed25519.to_i64()));
        let pkey =
            PKey::public_key_from_raw_bytes(x, Id::ED25519).context("Failed to instantiate key")?;
        Ok(Self { kind: Kind::Ed25519, pkey })
    }

    fn from_cose_ec2_key(pkey: &CoseKey) -> Result<Self> {
        ensure!(pkey.kty == KeyType::Assigned(iana::KeyType::EC2));
        let crv = get_label_value(pkey, Label::Int(iana::Ec2KeyParameter::Crv.to_i64()))?;
        let x = get_label_value_as_bytes(pkey, Label::Int(iana::Ec2KeyParameter::X.to_i64()))?;
        let y = get_label_value_as_bytes(pkey, Label::Int(iana::Ec2KeyParameter::Y.to_i64()))?;
        match pkey.alg {
            Some(Algorithm::Assigned(iana::Algorithm::ES256)) => {
                ensure!(crv == &Value::from(iana::EllipticCurve::P_256.to_i64()));
                let pkey = Self::ec_pkey_from_bytes(Nid::X9_62_PRIME256V1, x, y)
                    .context("Failed to instantiate key")?;
                Ok(Self { kind: Kind::Ec(EcKind::P256), pkey })
            }
            Some(Algorithm::Assigned(iana::Algorithm::ES384)) => {
                ensure!(crv == &Value::from(iana::EllipticCurve::P_384.to_i64()));
                let pkey = Self::ec_pkey_from_bytes(Nid::SECP384R1, x, y)
                    .context("Failed to instantiate key")?;
                Ok(Self { kind: Kind::Ec(EcKind::P384), pkey })
            }
            _ => bail!("Need to specify ES256 or ES384 in the key. Got {:?}", pkey.alg),
        }
    }

    fn ec_pkey_from_bytes(nid: Nid, x_coord: &[u8], y_coord: &[u8]) -> Result<PKey<Public>> {
        let group = EcGroup::from_curve_name(nid).context("Failed to construct curve group")?;
        let x = BigNum::from_slice(x_coord).context("Failed to create x coord")?;
        let y = BigNum::from_slice(y_coord).context("Failed to create y coord")?;
        let key = EcKey::from_public_key_affine_coordinates(&group, &x, &y)
            .context("Failed to create EC public key")?;
        PKey::from_ec_key(key).context("Failed to create PKey")
    }

    pub(super) fn algorithm(&self) -> Algorithm {
        match self.kind {
            Kind::Ed25519 => Algorithm::Assigned(iana::Algorithm::EdDSA),
            Kind::Ec(EcKind::P256) => Algorithm::Assigned(iana::Algorithm::ES256),
            Kind::Ec(EcKind::P384) => Algorithm::Assigned(iana::Algorithm::ES384),
        }
    }

    fn verify_ed25519(&self, signature: &[u8], message: &[u8]) -> Result<bool> {
        ensure!(signature.len() == 64, "Wrong signature length: {:?}", signature.len());
        let mut verifier =
            Verifier::new_without_digest(&self.pkey).context("Failed to create verifier")?;
        verifier.verify_oneshot(signature, message).context("Failed to verify signature")
    }

    fn verify_ec(&self, ec: EcKind, signature: &[u8], message: &[u8]) -> Result<bool> {
        let (coord_len, digest) = match ec {
            EcKind::P256 => (32, MessageDigest::sha256()),
            EcKind::P384 => (48, MessageDigest::sha384()),
        };
        let sig_len = coord_len * 2;
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
        let verified = match self.kind {
            Kind::Ed25519 => self.verify_ed25519(signature, message)?,
            Kind::Ec(ec) => self
                .verify_ec(ec, signature, message)
                .with_context(|| format!("Failed to verify EC {:?} signature", ec))?,
        };
        ensure!(verified, "Signature verification failed.");
        Ok(())
    }

    /// Serializes the public key into a PEM-encoded SubjectPublicKeyInfo structure.
    pub fn to_pem(&self) -> String {
        String::from_utf8(self.pkey.public_key_to_pem().unwrap()).unwrap()
    }
}

/// The error type returned when converting from [`PKey'] to [`PublicKey`] fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TryFromPKeyError(());

impl fmt::Display for TryFromPKeyError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "unsupported public key conversion attempted")
    }
}

impl Error for TryFromPKeyError {}

impl TryFrom<PKey<Public>> for PublicKey {
    type Error = TryFromPKeyError;

    fn try_from(pkey: PKey<Public>) -> Result<Self, Self::Error> {
        let kind = match pkey.id() {
            Id::ED25519 => Kind::Ed25519,
            Id::EC => match pkey.ec_key().unwrap().group().curve_name() {
                Some(Nid::X9_62_PRIME256V1) => Kind::Ec(EcKind::P256),
                Some(Nid::SECP384R1) => Kind::Ec(EcKind::P384),
                _ => return Err(TryFromPKeyError(())),
            },
            _ => return Err(TryFromPKeyError(())),
        };
        Ok(Self { kind, pkey })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_ed25519_pkey() {
        let pkey = load_public_pkey(testkeys::ED25519_KEY_PEM[0]);
        let key: PublicKey = pkey.clone().try_into().unwrap();
        assert_eq!(key.to_pem().as_bytes(), pkey.public_key_to_pem().unwrap());
    }

    #[test]
    fn from_p256_pkey() {
        let pkey = load_public_pkey(testkeys::P256_KEY_PEM[0]);
        let key: PublicKey = pkey.clone().try_into().unwrap();
        assert_eq!(key.to_pem().as_bytes(), pkey.public_key_to_pem().unwrap());
    }

    #[test]
    fn from_p384_pkey() {
        let pkey = load_public_pkey(testkeys::P384_KEY_PEM[0]);
        let key: PublicKey = pkey.clone().try_into().unwrap();
        assert_eq!(key.to_pem().as_bytes(), pkey.public_key_to_pem().unwrap());
    }

    #[test]
    fn from_p521_pkey_not_supported() {
        let pkey = load_public_pkey(testkeys::P521_KEY_PEM[0]);
        assert!(PublicKey::try_from(pkey).is_err());
    }

    #[test]
    fn from_rsa2048_pkey_not_supported() {
        let pkey = load_public_pkey(testkeys::RSA2048_KEY_PEM[0]);
        assert!(PublicKey::try_from(pkey).is_err());
    }

    pub fn load_public_pkey(pem: &str) -> PKey<Public> {
        testkeys::public_from_private(&PKey::private_key_from_pem(pem.as_bytes()).unwrap())
    }
}

/// Keys and key handling utilities for use in tests.
#[cfg(test)]
pub(crate) mod testkeys {
    use super::*;
    use openssl::pkey::Private;

    /// Gives the public key that matches the private key.
    pub fn public_from_private(pkey: &PKey<Private>) -> PKey<Public> {
        // It feels like there should be a more direct way to do this but I haven't found it.
        PKey::public_key_from_der(&pkey.public_key_to_der().unwrap()).unwrap()
    }

    /// A selection of Ed25519 private keys.
    pub const ED25519_KEY_PEM: &[&str] = &["-----BEGIN PRIVATE KEY-----\n\
        MC4CAQAwBQYDK2VwBCIEILKW0KEeuieFxhDAzigQPE4XRTiQx+0/AlAjJqHmUWE6\n\
        -----END PRIVATE KEY-----\n"];

    /// A selection of elliptic curve P-256 private keys.
    pub const P256_KEY_PEM: &[&str] = &["-----BEGIN PRIVATE KEY-----\n\
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg+CO3ZBuAsimwPKAL\n\
        IeDyCh4cRZ5EMd6llGu5MQCpibGhRANCAAQObPxc4bIPjupILrvKJjTrpTcyCf6q\n\
        V552FlS67fGphwhg2LDfQ8adEdkuRfQvk+IvKJz8MDcPjErBG3Wlps1N\n\
        -----END PRIVATE KEY-----\n"];

    /// A selection of elliptic curve P-384 private keys.
    pub const P384_KEY_PEM: &[&str] = &["-----BEGIN PRIVATE KEY-----\n\
        MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBMZ414LiUpcuNTNq5W\n\
        Ig/qbnbFn0MpuZZxUn5YZ8/+2/tyXFFHRyQoQ4YpNN1P/+qhZANiAAScPDyisb21\n\
        GldmGksI5g82hjPRYscWNs/6pFxQTMcxABE+/1lWaryLR193ZD74VxVRIKDBluRs\n\
        uuHi+VayOreTX1/qlUoxgBT+XTI0nTdLn6WwO6vVO1NIkGEVnYvB2eM=\n\
        -----END PRIVATE KEY-----\n"];

    /// A selection of elliptic curve P-521 private keys.
    pub const P521_KEY_PEM: &[&str] = &["-----BEGIN PRIVATE KEY-----\n\
        MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBQuD8Db3jT2yPYR5t\n\
        Y1ZqESxOe4eBWzekFKg7cjVWsSiJEvWTPC1H7CLtXQBHZglO90dwMt4flL91xHkl\n\
        iZOzyHahgYkDgYYABAHACwmmKkZu01fp1QTTTQ0cv7IAfYv9FEBz8yfhNGPnI2WY\n\
        iH1/lYeCfYc9d33aSc/ELY9+vIFzVStJumS/B/WTewEhxVomlKPAkUJeLdCaK5av\n\
        nlUNj7pNQ/5v5FZVxmoFJvAtUAnZqnJqo/QkLtEnmKlzpLte2LuwTPZhG35z0HeL\n\
        2g==\n\
        -----END PRIVATE KEY-----\n"];

    /// A selection of 2048-bit RSA private keys.
    pub const RSA2048_KEY_PEM: &[&str] = &["-----BEGIN PRIVATE KEY-----\n\
        MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDbOJh7Ys7CuIju\n\
        VVKMlFlZWwDEGBX5bVYD/xNBNNF1FY9bOcV/BG20IwoZkdV0N+vm8eWSuv/uwIJp\n\
        sN2PMWPAEIWbPGGMnSdePpkwrdpFFywhEQqUrfdCFXZ8zeF85Nz5mL8ysl4vlMsL\n\
        mbErCkrq++K0lzs+k7w/FtPCgs4M3WypJfZef5zM0CGWxpHZGoUGm0HW9fen4sv8\n\
        hTmMGNY/r0SJhdZREGmiGCx2v+ksOEBon1r/6QKVTP8S73XFsyNCWyop0hYTakut\n\
        D3HtJ5sWzu2RU8rrch3Txinz0jpGF8PATHk35YMw/9jwwwSqjDw+pOQcYk8SviAf\n\
        glZf8aZlAgMBAAECggEAAS67PK67tuaOWywJSWHLsWGmqJ4I2tZiTzCT9EZ2MOVx\n\
        +4ZChNfjHUsskXUp4XNL/FE0J3WvhEYjXR1u+L37nvqc48mJpjoPN7o/CMb6rM/J\n\
        +ly9A2ZOvEB4ppOYDYh5QVDm7/otmvEMzJxuUOpvxYxqnJpAPgl9dBpNQ0nSt3YX\n\
        jJS4+vuzQpwwSTfchpcCZYU3AX9DpQpxnrLX3/7d3GTs2NuedmSwRz+mCfwaOlFk\n\
        jdrJ2uJJrDLcK6yhSdsE9aNgKkmX6aNLhxbbCFTyDNiGY5HHayyL3mVvyaeovYcn\n\
        ZS+Z+0TJGCgXDRHHSFyIAsgVonxHfn49x9uvfpuMFQKBgQD2cVp26+aQgt46ajVv\n\
        yn4fxbNpfovL0pgtSjo7ekZOWYJ3Is1SDmnni8k1ViKgUYC210dTTlrljxUil8T0\n\
        83e03k2xasDi2c+h/7JFYJPDyZwIm1o19ciUwY73D54iJaRbrzEximFeA0h4LGKw\n\
        Yjd4xkKMJw16CU00gInyI193BwKBgQDjuP0/QEEPpYvzpag5Ul4+h22K/tiOUrFj\n\
        NuSgd+IvQG1hW48zHEa9vXvORQ/FteiQ708racz6ByqY+n2w6QdtdRMj7Hsyo2fk\n\
        SEeNaLrR7Sif6MfkYajbSGFySDD82vj4Jt76vzdt3MjpZfs6ryPmnKLVPWNA3mnS\n\
        4+u2J/+QMwKBgFfiJnugNnG0aaF1PKcoFAAqlYd6XEoMSL5l6QxK14WbP/5SR9wK\n\
        TdQHsnI1zFVVm0wYy1O27o1MkCHs84zSwg6a9CPfyPdc60F/GMjK3wcD/4PGOs5h\n\
        Xu1FdUE/rYnJ2KnleOqMyZooG5DXaz4xWEzWjubCCnlJleGyMP9LhADDAoGAR/jK\n\
        iXgcV/6haeMcdOl0gdy5oWmENg8qo0nRHmplYTvCljei3at9LDC79WhcYMdqdow8\n\
        AGOS9h7XtrvMh+JOh6it4Pe3xDxi9IJnoujLytditI+Uxbib7ppEuiLY4MGwWHWo\n\
        maVftmhGU4X4zgZWmWc+C5k4SmNBHPcOI2cm3YMCgYB5/Ni+tBxng0S/PRAtwCeG\n\
        dVnQnYvS2C5nHCn9D5rmAcVXUKrIJ1/1K4se8vQ15DDcpuBF1SejYTJzdUP8Zgcs\n\
        p8wVq7neK8uSsmG+AfUgxMjbetoAVTP3L8+GbjocznR9auB7BEjFVO25iYSiTp/w\n\
        NNzbIKQRDN+c3vUpneJcuw==\n\
        -----END PRIVATE KEY-----\n"];
}
