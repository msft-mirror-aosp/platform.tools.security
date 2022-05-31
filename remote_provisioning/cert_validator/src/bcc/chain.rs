//! This module provides a wrapper describing a valid Boot Certificate Chain.

use super::cose_error;
use super::entry::Payload;
use super::entry::SubjectPublicKey;
use anyhow::{Context, Result};
use coset::{
    cbor::value::Value::{self, Array},
    AsCborValue, CborSerializable,
    CoseError::{self, EncodeFailed, UnexpectedItem},
    CoseKey, CoseSign1,
};
use std::fmt::{self, Display, Formatter};

/// Represents a full Boot Certificate Chain (BCC). This consists of the root public key (which
/// signs the first certificate), followed by a chain of BccEntry certificates. Apart from the
/// first, the issuer of each cert is the subject of the previous one.
pub struct Chain {
    root_public_key: SubjectPublicKey,
    payloads: Vec<Payload>,
}

impl Chain {
    /// Decode and validate a Chain from its CBOR representation. This ensures the CBOR is
    /// well-formed, that all required fields are present, and all present fields contain
    /// reasonable values. The signature of each certificate is validated and the payload
    /// extracted. This does not perform any semantic validation of the data in the
    /// certificates such as the Authority, Config and Code hashes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let raw = RawChain::from_slice(bytes).map_err(cose_error)?;

        let root_public_key = SubjectPublicKey::from_cose_key(raw.public_key);
        root_public_key.check().context("Invalid root key")?;

        let mut payloads = Vec::<Payload>::with_capacity(raw.entries.len());
        let mut previous = payloads.last();
        for (n, entry) in raw.entries.iter().enumerate() {
            let payload = match previous {
                None => Payload::check_sign1_signature(&root_public_key, entry),
                Some(payload) => payload.check_sign1(entry),
            }
            .with_context(|| format!("Failed signature check of certificate at index {}", n))?;
            payload.check().with_context(|| format!("Invalid BccPayload at index {}", n))?;
            payloads.push(payload);
            previous = payloads.last();
        }

        Ok(Self { root_public_key, payloads })
    }
}

impl Display for Chain {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        writeln!(f, "Root public key: {}", self.root_public_key)?;
        writeln!(f)?;
        for (i, payload) in self.payloads.iter().enumerate() {
            writeln!(f, "Cert {}:", i)?;
            writeln!(f, "{}", payload)?;
        }
        Ok(())
    }
}

// The COSE data parsed from a CBOR BCC.
struct RawChain {
    public_key: CoseKey,
    entries: Vec<CoseSign1>,
}

impl AsCborValue for RawChain {
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
        Ok(Self { public_key, entries })
    }

    fn to_cbor_value(self) -> Result<Value, CoseError> {
        // TODO: Implement when needed
        Err(EncodeFailed)
    }
}

impl CborSerializable for RawChain {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_check_chain_valid() -> Result<()> {
        let chain = fs::read("testdata/bcc/valid.chain").unwrap();
        let chain = Chain::from_bytes(&chain)?;
        assert_eq!(chain.payloads.len(), 8);
        Ok(())
    }

    #[test]
    fn test_check_chain_valid_p256() -> Result<()> {
        let chain = fs::read("testdata/bcc/valid_p256.chain").unwrap();
        let chain = Chain::from_bytes(&chain)?;
        assert_eq!(chain.payloads.len(), 3);
        Ok(())
    }

    #[test]
    fn test_check_chain_bad_p256() {
        let chain = fs::read("testdata/bcc/bad_p256.chain").unwrap();
        assert!(Chain::from_bytes(&chain).is_err());
    }

    #[test]
    fn test_check_chain_bad_pub_key() {
        let chain = fs::read("testdata/bcc/bad_pub_key.chain").unwrap();
        assert!(Chain::from_bytes(&chain).is_err());
    }

    #[test]
    fn test_check_chain_bad_final_signature() {
        let chain = fs::read("testdata/bcc/bad_final_signature.chain").unwrap();
        assert!(Chain::from_bytes(&chain).is_err());
    }
}
