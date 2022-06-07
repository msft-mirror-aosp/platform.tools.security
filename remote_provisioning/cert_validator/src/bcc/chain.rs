//! This module provides a wrapper describing a valid Boot Certificate Chain.

use super::cose_error;
use super::entry::{check_sign1_chain, Payload, SubjectPublicKey};
use anyhow::{bail, Context, Result};
use coset::{cbor::value::Value::Array, AsCborValue, CoseKey};
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
        /*
         * CDDL (from keymint/ProtectedData.aidl):
         *
         * Bcc = [
         *     PubKeyEd25519 / PubKeyECDSA256, // DK_pub
         *     + BccEntry,                     // Root -> leaf (KM_pub)
         * ]
         */

        let value = ciborium::de::from_reader(bytes).context("Decoding CBOR BCC failed")?;
        let array = match value {
            Array(array) if array.len() >= 2 => array,
            _ => bail!("Invalid BCC: {:?}", value),
        };
        let mut it = array.into_iter();

        let root_public_key = CoseKey::from_cbor_value(it.next().unwrap()).map_err(cose_error)?;
        let root_public_key = SubjectPublicKey::from_cose_key(root_public_key);
        root_public_key.check().context("Invalid root key")?;

        let payloads = check_sign1_chain(it, Some(&root_public_key))?;

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
