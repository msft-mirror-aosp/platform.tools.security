//! This module provides a wrapper describing a valid Boot Certificate Chain.

use super::cose_error;
use super::entry::Payload;
use crate::publickey::PublicKey;
use crate::value_from_bytes;
use anyhow::{bail, ensure, Context, Result};
use ciborium::value::Value;
use coset::{cbor::value::Value::Array, AsCborValue, CoseKey};
use std::fmt::{self, Display, Formatter};

/// Parse a series of BccEntry certificates, represented as CBOR Values, checking the public key of
/// any given cert's payload in the series correctly signs the next, and verifying the payloads
/// are well formed. If root_key is specified then it must be the key used to sign the first (root)
/// certificate; otherwise that signature is not checked.
fn check_sign1_chain<T: IntoIterator<Item = Value>>(
    chain: T,
    root_key: Option<&PublicKey>,
) -> Result<Vec<Payload>> {
    let values = chain.into_iter();
    let mut payloads = Vec::<Payload>::with_capacity(values.size_hint().0);

    let mut previous_public_key = root_key;
    let mut expected_issuer: Option<&str> = None;

    for (n, value) in values.enumerate() {
        let payload = Payload::from_cbor_sign1(previous_public_key, expected_issuer, value)
            .with_context(|| format!("Invalid BccPayload at index {}", n))?;
        payloads.push(payload);

        let previous = payloads.last().unwrap();
        expected_issuer = Some(previous.subject.as_str());
        previous_public_key = Some(&previous.subject_public_key);
    }

    ensure!(!payloads.is_empty(), "Cert chain is empty.");

    Ok(payloads)
}

/// Represents a full Boot Certificate Chain (BCC). This consists of the root public key (which
/// signs the first certificate), followed by a chain of BccEntry certificates. Apart from the
/// first, the issuer of each cert is the subject of the previous one.
pub struct Chain {
    root_public_key: PublicKey,
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

        let value = value_from_bytes(bytes).context("Unable to decode top-level CBOR")?;
        let array = match value {
            Array(array) if array.len() >= 2 => array,
            _ => bail!("Invalid BCC. Expected an array of at least length 2, found: {:?}", value),
        };
        let mut it = array.into_iter();

        let root_public_key = CoseKey::from_cbor_value(it.next().unwrap())
            .map_err(cose_error)
            .context("Error parsing root public key CBOR")?;
        let root_public_key =
            PublicKey::from_cose_key(&root_public_key).context("Invalid root key")?;

        let payloads =
            check_sign1_chain(it, Some(&root_public_key)).context("Invalid certificate chain")?;

        Ok(Self { root_public_key, payloads })
    }

    /// Get the root public key which verifies the first certificate in the chain.
    pub fn root_public_key(&self) -> &PublicKey {
        &self.root_public_key
    }

    /// Get the payloads of the certificates in the chain, from root to leaf.
    pub fn payloads(&self) -> &[Payload] {
        &self.payloads
    }

    /// Get the payload from the final certificate in the chain.
    pub fn leaf(&self) -> &Payload {
        // There is always at least one payload.
        self.payloads.last().unwrap()
    }
}

impl Display for Chain {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        writeln!(f, "Root public key:")?;
        writeln!(f, "{}", self.root_public_key.to_pem())?;
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
    use crate::value_from_file;
    use std::fs;

    #[test]
    fn test_check_chain_valid() -> Result<()> {
        let chain = fs::read("testdata/bcc/valid.chain").unwrap();
        let chain = Chain::from_bytes(&chain)?;
        assert_eq!(chain.payloads().len(), 8);
        Ok(())
    }

    #[test]
    fn test_check_chain_valid_p256() -> Result<()> {
        let chain = fs::read("testdata/bcc/valid_p256.chain").unwrap();
        let chain = Chain::from_bytes(&chain)?;
        assert_eq!(chain.payloads().len(), 3);
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

    #[test]
    fn test_check_sign1_cert_chain() -> Result<()> {
        let chain = [
            value_from_file("testdata/bcc/_CBOR_Ed25519_cert_full_cert_chain_0.cert")?,
            value_from_file("testdata/bcc/_CBOR_Ed25519_cert_full_cert_chain_1.cert")?,
            value_from_file("testdata/bcc/_CBOR_Ed25519_cert_full_cert_chain_2.cert")?,
        ];
        let root_key = None;
        check_sign1_chain(chain, root_key)?;
        Ok(())
    }

    #[test]
    fn test_check_sign1_cert_chain_invalid() -> Result<()> {
        let chain = [
            value_from_file("testdata/bcc/_CBOR_Ed25519_cert_full_cert_chain_0.cert")?,
            value_from_file("testdata/bcc/_CBOR_Ed25519_cert_full_cert_chain_2.cert")?,
        ];
        let root_key = None;
        assert!(check_sign1_chain(chain, root_key).is_err());
        Ok(())
    }

    #[test]
    fn test_check_sign1_chain_array() -> Result<()> {
        let cbor_file = value_from_file("testdata/bcc/_CBOR_bcc_entry_cert_array.cert")?;
        let cbor_arr = match cbor_file {
            Value::Array(a) => a,
            _ => bail!("Not an array"),
        };
        assert_eq!(cbor_arr.len(), 3);
        let root_key = None;
        check_sign1_chain(cbor_arr, root_key)?;
        Ok(())
    }
}
