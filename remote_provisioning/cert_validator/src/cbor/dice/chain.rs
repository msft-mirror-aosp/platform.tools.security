use crate::bcc::entry::Payload;
use crate::bcc::Chain;
use crate::cbor::{cose_error, value_from_bytes};
use crate::publickey::PublicKey;
use anyhow::{bail, ensure, Context, Result};
use ciborium::value::Value;
use coset::{cbor::value::Value::Array, AsCborValue, CoseKey};

impl Chain {
    /// Decode and validate a Chain from its CBOR representation. This ensures the CBOR is
    /// well-formed, that all required fields are present, and all present fields contain
    /// reasonable values. The signature of each certificate is validated and the payload
    /// extracted. This does not perform any semantic validation of the data in the
    /// certificates such as the Authority, Config and Code hashes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
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

        Ok(Self::new(root_public_key, payloads))
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn check_chain_valid_ed25519() {
        let chain = fs::read("testdata/bcc/valid_ed25519.chain").unwrap();
        let chain = Chain::from_cbor(&chain).unwrap();
        assert_eq!(chain.payloads().len(), 8);
    }

    #[test]
    fn check_chain_valid_p256() {
        let chain = fs::read("testdata/bcc/valid_p256.chain").unwrap();
        let chain = Chain::from_cbor(&chain).unwrap();
        assert_eq!(chain.payloads().len(), 3);
    }

    #[test]
    fn check_chain_bad_p256() {
        let chain = fs::read("testdata/bcc/bad_p256.chain").unwrap();
        assert!(Chain::from_cbor(&chain).is_err());
    }

    #[test]
    fn check_chain_bad_pub_key() {
        let chain = fs::read("testdata/bcc/bad_pub_key.chain").unwrap();
        assert!(Chain::from_cbor(&chain).is_err());
    }

    #[test]
    fn check_chain_bad_final_signature() {
        let chain = fs::read("testdata/bcc/bad_final_signature.chain").unwrap();
        assert!(Chain::from_cbor(&chain).is_err());
    }
}
