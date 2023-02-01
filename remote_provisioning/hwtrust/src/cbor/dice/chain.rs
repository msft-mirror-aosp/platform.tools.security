use super::entry::Entry;
use crate::cbor::dice::entry::PayloadFields;
use crate::cbor::{cose_error, value_from_bytes};
use crate::dice::{Chain, ChainForm, DegenerateChain, Payload};
use crate::publickey::PublicKey;
use anyhow::{bail, Context, Result};
use ciborium::value::Value;
use coset::{cbor::value::Value::Array, AsCborValue, CoseKey};

impl ChainForm {
    /// Decode and validate a CBOR-encoded DICE chain. The form of chain is inferred from the
    /// structure of the data.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        let (root_public_key, it) = root_and_entries_from_cbor(bytes)?;

        if it.len() == 1 {
            // The chain could be degenerate so interpret it as such until it's seen to be more
            // than a single self-signed entry. Care is taken to not consume the iterator in case
            // it ends up needing to be interpreted as a proper DICE chain.
            let value = it.as_slice()[0].clone();
            let entry = Entry::verify_cbor_value(value, &root_public_key)
                .context("parsing degenerate entry")?;
            let fields =
                PayloadFields::from_cbor(entry.payload()).context("parsing degenerate payload")?;
            let chain =
                DegenerateChain::new(fields.issuer, fields.subject, fields.subject_public_key)
                    .context("creating DegenerateChain")?;
            if root_public_key.pkey().public_eq(chain.public_key().pkey()) {
                return Ok(Self::Degenerate(chain));
            }
        }

        Ok(Self::Proper(Chain::from_root_and_entries(root_public_key, it)?))
    }
}

impl Chain {
    /// Decode and validate a Chain from its CBOR representation. This ensures the CBOR is
    /// well-formed, that all required fields are present, and all present fields contain
    /// reasonable values. The signature of each certificate is validated and the payload
    /// extracted. This does not perform any semantic validation of the data in the
    /// certificates such as the Authority, Config and Code hashes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        let (root_public_key, it) = root_and_entries_from_cbor(bytes)?;
        Self::from_root_and_entries(root_public_key, it)
    }

    fn from_root_and_entries(root: PublicKey, values: std::vec::IntoIter<Value>) -> Result<Self> {
        let mut payloads = Vec::with_capacity(values.len());
        let mut previous_public_key = &root;
        for (n, value) in values.enumerate() {
            let entry = Entry::verify_cbor_value(value, previous_public_key)
                .with_context(|| format!("Invalid entry at index {}", n))?;
            let payload = Payload::from_cbor(entry.payload())
                .with_context(|| format!("Invalid payload at index {}", n))?;
            payloads.push(payload);
            let previous = payloads.last().unwrap();
            previous_public_key = previous.subject_public_key();
        }
        Self::validate(root, payloads).context("Building chain")
    }
}

fn root_and_entries_from_cbor(bytes: &[u8]) -> Result<(PublicKey, std::vec::IntoIter<Value>)> {
    let value = value_from_bytes(bytes).context("Unable to decode top-level CBOR")?;
    let array = match value {
        Array(array) if array.len() >= 2 => array,
        _ => bail!("Expected an array of at least length 2, found: {:?}", value),
    };
    let mut it = array.into_iter();
    let root_public_key = CoseKey::from_cbor_value(it.next().unwrap())
        .map_err(cose_error)
        .context("Error parsing root public key CBOR")?;
    let root_public_key = PublicKey::from_cose_key(&root_public_key).context("Invalid root key")?;
    Ok((root_public_key, it))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::serialize;
    use crate::dice::{DiceMode, PayloadBuilder};
    use crate::publickey::testkeys::{PrivateKey, ED25519_KEY_PEM, P256_KEY_PEM, P384_KEY_PEM};
    use std::fs;

    #[test]
    fn chain_form_valid_proper() {
        let chain = fs::read("testdata/dice/valid_ed25519.chain").unwrap();
        let form = ChainForm::from_cbor(&chain).unwrap();
        assert!(matches!(form, ChainForm::Proper(_)));
    }

    #[test]
    fn chain_form_valid_degenerate() {
        let chain = fs::read("testdata/dice/cf_degenerate.chain").unwrap();
        let form = ChainForm::from_cbor(&chain).unwrap();
        assert!(matches!(form, ChainForm::Degenerate(_)));
    }

    #[test]
    fn check_chain_valid_ed25519() {
        let chain = fs::read("testdata/dice/valid_ed25519.chain").unwrap();
        let chain = Chain::from_cbor(&chain).unwrap();
        assert_eq!(chain.payloads().len(), 8);
    }

    #[test]
    fn check_chain_valid_p256() {
        let chain = fs::read("testdata/dice/valid_p256.chain").unwrap();
        let chain = Chain::from_cbor(&chain).unwrap();
        assert_eq!(chain.payloads().len(), 3);
    }

    #[test]
    fn check_chain_bad_p256() {
        let chain = fs::read("testdata/dice/bad_p256.chain").unwrap();
        assert!(Chain::from_cbor(&chain).is_err());
    }

    #[test]
    fn check_chain_bad_pub_key() {
        let chain = fs::read("testdata/dice/bad_pub_key.chain").unwrap();
        assert!(Chain::from_cbor(&chain).is_err());
    }

    #[test]
    fn check_chain_bad_final_signature() {
        let chain = fs::read("testdata/dice/bad_final_signature.chain").unwrap();
        assert!(Chain::from_cbor(&chain).is_err());
    }

    #[test]
    fn chain_from_cbor_valid() {
        let keys: Vec<_> = P256_KEY_PEM[..4].iter().copied().map(PrivateKey::from_pem).collect();
        let mut pub_keys = keys.iter().map(PrivateKey::public_key);
        let root_key = pub_keys.next().unwrap().to_cose_key().unwrap().to_cbor_value().unwrap();
        let mut chain = vec![root_key];
        chain.extend(pub_keys.enumerate().map(|(n, key)| {
            let entry = Entry::from_payload(&valid_payload(n, key)).unwrap();
            entry.sign(&keys[n]).to_cbor_value().unwrap()
        }));
        Chain::from_cbor(&serialize(Value::Array(chain))).unwrap();
    }

    #[test]
    fn chain_from_cbor_valid_with_mixed_key_types() {
        let keys = [ED25519_KEY_PEM[0], P256_KEY_PEM[0], P384_KEY_PEM[0]];
        let keys: Vec<_> = keys.iter().copied().map(PrivateKey::from_pem).collect();
        let mut pub_keys = keys.iter().map(PrivateKey::public_key);
        let root_key = pub_keys.next().unwrap().to_cose_key().unwrap().to_cbor_value().unwrap();
        let mut chain = vec![root_key];
        chain.extend(pub_keys.enumerate().map(|(n, key)| {
            let entry = Entry::from_payload(&valid_payload(n, key)).unwrap();
            entry.sign(&keys[n]).to_cbor_value().unwrap()
        }));
        Chain::from_cbor(&serialize(Value::Array(chain))).unwrap();
    }

    #[test]
    fn chain_form_from_cbor_valid_degenerate() {
        let key = PrivateKey::from_pem(P256_KEY_PEM[0]);
        let pub_key = key.public_key();
        let entry = Entry::from_payload(&valid_payload(0, pub_key.clone())).unwrap();
        let chain = vec![
            pub_key.to_cose_key().unwrap().to_cbor_value().unwrap(),
            entry.sign(&key).to_cbor_value().unwrap(),
        ];
        let form = ChainForm::from_cbor(&serialize(Value::Array(chain))).unwrap();
        assert!(matches!(form, ChainForm::Degenerate(_)));
    }

    /// Tests that a chain the length of a degenerate chain that does not contain a self-signed
    /// certificate is a proper DICE chain and not a degenerate chain.
    #[test]
    fn chain_form_from_cbor_degenerate_length_but_not_self_signed() {
        let root_key = PrivateKey::from_pem(P256_KEY_PEM[0]);
        let entry_pub_key = PrivateKey::from_pem(ED25519_KEY_PEM[0]).public_key();
        let entry = Entry::from_payload(&valid_payload(0, entry_pub_key)).unwrap();
        let chain = vec![
            root_key.public_key().to_cose_key().unwrap().to_cbor_value().unwrap(),
            entry.sign(&root_key).to_cbor_value().unwrap(),
        ];
        let form = ChainForm::from_cbor(&serialize(Value::Array(chain))).unwrap();
        assert!(matches!(form, ChainForm::Proper(_)));
    }

    fn valid_payload(index: usize, key: PublicKey) -> Payload {
        PayloadBuilder::with_subject_public_key(key)
            .issuer(format!("item {}", index))
            .subject(format!("item {}", index + 1))
            .mode(DiceMode::Normal)
            .code_hash(vec![6; 64])
            .authority_hash(vec![7; 64])
            .build()
            .unwrap()
    }
}
