//! This module provides functions for validating chains of bcc certificates

pub mod entry;

use self::entry::SubjectPublicKey;
use anyhow::{anyhow, Context, Result};
use coset::AsCborValue;
use coset::{
    cbor::value::Value::{self, Array},
    CborSerializable,
    CoseError::{self, EncodeFailed, UnexpectedItem},
    CoseKey, CoseSign1,
};
use std::io::Read;

/// Represents a full Boot Certificate Chain (BCC). This consists of the root public key (which
/// signs the first certificate), followed by a chain of BccEntry certificates. Apart from the
/// first, the issuer of each cert if the subject of the previous one.
pub struct Chain {
    public_key: CoseKey,
    entries: Vec<CoseSign1>,
}

impl Chain {
    /// Read a Chain from a file containing the CBOR encoding. This fails if the representation is
    /// ill-formed.
    pub fn read(fname: &str) -> Result<Chain> {
        let mut f = std::fs::File::open(fname)?;
        let mut content = Vec::new();
        f.read_to_end(&mut content)?;
        Chain::from_slice(&content).map_err(cose_error)
    }

    /// Check all certificates are correctly signed, contain the required fields, and are otherwise
    /// semantically correct.
    pub fn check(&self) -> Result<Vec<entry::Payload>> {
        let public_key = SubjectPublicKey::from_cose_key(self.public_key.clone());
        public_key.check().context("Invalid root key")?;

        let mut payloads = Vec::<entry::Payload>::with_capacity(self.entries.len());
        let mut previous = payloads.last();
        for (n, entry) in self.entries.iter().enumerate() {
            let payload = match previous {
                None => entry::Payload::check_sign1_signature(&public_key, entry),
                Some(payload) => payload.check_sign1(entry),
            }
            .with_context(|| format!("Failed signature check of certificate at index {}", n))?;
            payload.check().with_context(|| format!("Invalid BccPayload at index {}", n))?;
            payloads.push(payload);
            previous = payloads.last();
        }
        Ok(payloads)
    }

    /// Return the public key that can be used to verify the signature on the first certificate in
    /// the chain.
    pub fn get_root_public_key(&self) -> SubjectPublicKey {
        SubjectPublicKey::from_cose_key(self.public_key.clone())
    }
}

impl AsCborValue for Chain {
    /*
     * CDDL (from keymint/ProtectedData.aidl):
     *
     * Bcc = [
     *     PubKeyEd25519 / PubKeyECDSA256, // DK_pub
     *     + BccEntry,                     // Root -> leaf (KM_pub)
     * ]
     */

    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
        let a = match value {
            Array(a) if a.len() >= 2 => a,
            _ => return Err(UnexpectedItem("something", "an array with 2 or more items")),
        };
        let mut it = a.into_iter();
        let public_key = CoseKey::from_cbor_value(it.next().unwrap())?;
        let entries = it.map(CoseSign1::from_cbor_value).collect::<Result<Vec<_>, _>>()?;
        Ok(Chain { public_key, entries })
    }

    fn to_cbor_value(self) -> Result<Value, CoseError> {
        // TODO: Implement when needed
        Err(EncodeFailed)
    }
}

impl CborSerializable for Chain {}

fn cose_error(ce: coset::CoseError) -> anyhow::Error {
    anyhow!("CoseError: {:?}", ce)
}

/// Get the value corresponding to the provided label within the supplied CoseKey
/// or error if it's not present.
pub fn get_label_value(key: &coset::CoseKey, label: i64) -> Result<&Value> {
    Ok(&key
        .params
        .iter()
        .find(|(k, _)| k == &coset::Label::Int(label))
        .ok_or_else(|| anyhow!("Label {:?} not found", label))?
        .1)
}

/// Get the byte string for the corresponding label within the key if the label exists
/// and the value is actually a byte array.
pub fn get_label_value_as_bytes(key: &coset::CoseKey, label: i64) -> Result<&Vec<u8>> {
    get_label_value(key, label)?.as_bytes().ok_or_else(|| anyhow!("Value not a bstr."))
}
