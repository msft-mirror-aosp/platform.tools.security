//! This module provides functions for validating chains of bcc certificates

use crate::dice;
use crate::publickey;
use crate::valueas::ValueAs;

use anyhow::{anyhow, ensure, Context, Result};
use coset::{
    cbor::value::Value, iana, Algorithm, CborSerializable, CoseKey, CoseSign1, Header,
    RegisteredLabel,
};
use std::io::Read;

/// This module wraps the certificate validation functions intended for BccEntry.
pub mod entry {
    use super::*;

    /// Read a series of bcc file certificates and verify that the public key of
    /// any given cert's payload in the series correctly signs the next cose
    /// sign1 cert.
    pub fn check_sign1_cert_chain(certs: &[String]) -> Result<()> {
        ensure!(!certs.is_empty());
        let mut payload = Payload::from_sign1(&read(&certs[0])?)
            .context("Failed to read the first bccEntry payload")?;
        for item in certs.iter().skip(1) {
            payload.check().context("Validation of BccPayload entries failed.")?;
            payload =
                payload.check_sign1(&read(item)?).context("Failed to read the bccEntry payload")?;
        }
        Ok(())
    }

    /// Read a given cbor array containing bcc entries and verify that the public key
    /// of any given cert's payload in the series correctly signs the next cose sign1
    /// cert.
    pub fn check_sign1_chain_array(cbor_arr: &[Value]) -> Result<()> {
        ensure!(!cbor_arr.is_empty());

        let mut writeme: Vec<u8> = Vec::new();
        ciborium::ser::into_writer(&cbor_arr[0], &mut writeme)?;
        let mut payload =
            Payload::from_sign1(&CoseSign1::from_slice(&writeme).map_err(cose_error)?)
                .context("Failed to read bccEntry payload")?;
        for item in cbor_arr.iter().skip(1) {
            payload.check().context("Validation of BccPayload entries failed")?;
            writeme = Vec::new();
            ciborium::ser::into_writer(item, &mut writeme)?;
            let next_sign1 = &CoseSign1::from_slice(&writeme).map_err(cose_error)?;
            payload = payload.check_sign1(next_sign1).context("Failed to read bccEntry payload")?;
        }
        Ok(())
    }

    /// Read a file name as string and create the BccEntry as COSE_sign1 structure.
    pub fn read(fname: &str) -> Result<CoseSign1> {
        let mut f = std::fs::File::open(fname)?;
        let mut content = Vec::new();
        f.read_to_end(&mut content)?;
        CoseSign1::from_slice(&content).map_err(cose_error)
    }

    /// Validate the protected header of a bcc entry with respect to the provided
    /// alg (typically originating from the subject public key of the payload).
    pub fn check_protected_header(alg: &Option<Algorithm>, header: &Header) -> Result<()> {
        ensure!(&header.alg == alg);
        ensure!(header
            .crit
            .iter()
            .all(|l| l == &RegisteredLabel::Assigned(iana::HeaderParameter::Alg)));
        Ok(())
    }

    fn cose_error(ce: coset::CoseError) -> anyhow::Error {
        anyhow!("CoseError: {:?}", ce)
    }

    /// Struct describing BccPayload cbor of the BccEntry.
    #[derive(Debug)]
    pub struct Payload(Value);
    impl Payload {
        /// Construct the Payload from the parent BccEntry COSE_sign1 structure.
        pub fn from_sign1(sign1: &CoseSign1) -> Result<Payload> {
            Self::from_slice(sign1.payload.as_ref().ok_or_else(|| anyhow!("no payload"))?)
        }

        /// Validate entries in the Payload to be correct.
        pub fn check(&self) -> Result<()> {
            // Validate required fields.
            self.map_lookup(dice::ISS)?.as_string()?;
            self.map_lookup(dice::SUB)?.as_string()?;
            SubjectPublicKey::from_payload(self)?.check().context("Public key failed checking")?;
            self.map_lookup(dice::KEY_USAGE)?
                .as_bytes()
                .ok_or_else(|| anyhow!("Payload Key usage not bytes"))?;

            // Validate optional fields.
            self.0
                .check_bytes_val_if_key_in_map(dice::CODE_HASH)
                .context("Code Hash value not bytes.")?;
            self.0
                .check_bytes_val_if_key_in_map(dice::CODE_DESC)
                .context("Code Descriptor value not bytes.")?;
            self.0
                .check_bytes_val_if_key_in_map(dice::CONFIG_HASH)
                .context("Configuration Hash value not bytes.")?;
            self.0
                .check_bytes_val_if_key_in_map(dice::CONFIG_DESC)
                .context("Configuration descriptor value not bytes.")?;
            self.0
                .check_bytes_val_if_key_in_map(dice::AUTHORITY_HASH)
                .context("Authority Hash value not bytes.")?;
            self.0
                .check_bytes_val_if_key_in_map(dice::AUTHORITY_DESC)
                .context("Authority descriptor value not bytes.")?;
            self.0.check_bytes_val_if_key_in_map(dice::MODE).context("Mode value not bytes.")?;
            Ok(())
        }

        /// Verify that the public key of this payload correctly signs the provided
        /// BccEntry sign1 object.
        pub fn check_sign1(&self, sign1: &CoseSign1) -> Result<Payload> {
            let pkey = SubjectPublicKey::from_payload(self)
                .context("Failed to construct Public key from the Bcc payload.")?;
            check_protected_header(&pkey.0.alg, &sign1.protected.header)
                .context("Validation of bcc entry protected header failed.")?;

            let v = publickey::PublicKey::from_cose_key(&pkey.0)
                .context("Extracting the Public key from bcc payload's coseKey failed.")?;
            sign1
                .verify_signature(b"", |s, m| v.verify(s, m, &pkey.0.alg))
                .context("Payload's public key incorrectly signs the given cose_sign1 cert.")?;

            let new_payload = Payload::from_sign1(sign1)
                .context("Failed to extract bcc payload from cose_sign1")?;
            ensure!(
                self.map_lookup(dice::SUB)? == new_payload.map_lookup(dice::ISS)?,
                "Subject/Issuer mismatch"
            );
            Ok(new_payload)
        }

        fn from_slice(b: &[u8]) -> Result<Self> {
            Ok(Payload(coset::cbor::de::from_reader(b).map_err(|e| anyhow!("CborError: {}", e))?))
        }

        fn map_lookup(&self, key: i64) -> Result<&Value> {
            Ok(&self
                .0
                .as_map()
                .ok_or_else(|| anyhow!("not a map"))?
                .iter()
                .find(|(k, _v)| k == &Value::from(key))
                .ok_or_else(|| anyhow!("missing key {}", key))?
                .1)
        }
    }

    /// Struct wrapping the CoseKey for BccEntry.BccPayload.SubjectPublicKey
    /// and the methods used for its validation.
    pub struct SubjectPublicKey(CoseKey);
    impl SubjectPublicKey {
        /// Construct the SubjectPublicKey from the (bccEntry's) Payload.
        pub fn from_payload(payload: &Payload) -> Result<SubjectPublicKey> {
            let bytes = payload
                .map_lookup(dice::SUBJECT_PUBLIC_KEY)?
                .as_bytes()
                .ok_or_else(|| anyhow!("public key not bytes"))?;
            Ok(SubjectPublicKey(CoseKey::from_slice(bytes).map_err(cose_error)?))
        }

        /// Perform validation on the items in the public key.
        pub fn check(&self) -> Result<()> {
            let pkey = &self.0;
            ensure!(pkey.kty == coset::KeyType::Assigned(iana::KeyType::OKP));
            // TODO: Follow up cl - add the case for ECDSA.
            ensure!(pkey.alg == Some(coset::Algorithm::Assigned(iana::Algorithm::EdDSA)));
            if !pkey.key_ops.is_empty() {
                ensure!(pkey
                    .key_ops
                    .contains(&coset::KeyOperation::Assigned(iana::KeyOperation::Verify)));
            }
            let crv = &pkey
                .params
                .iter()
                .find(|(k, _)| k == &coset::Label::Int(iana::OkpKeyParameter::Crv as i64))
                .ok_or_else(|| anyhow!("Curve not found"))?
                .1;
            ensure!(crv == &Value::from(iana::EllipticCurve::Ed25519 as i64));
            Ok(())
        }
    }
}
