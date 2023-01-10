use super::field_value::FieldValue;
use crate::bcc::entry::{ConfigDesc, ConfigDescBuilder, DiceMode, Payload, PayloadBuilder};
use crate::cbor::{cose_error, value_from_bytes};
use crate::publickey::PublicKey;
use anyhow::{anyhow, bail, ensure, Context, Result};
use ciborium::value::Value;
use coset::{Algorithm, AsCborValue, CborSerializable, CoseKey, CoseSign1, Header};
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashMap;

const ISS: i64 = 1;
const SUB: i64 = 2;
const CODE_HASH: i64 = -4670545;
const CODE_DESC: i64 = -4670546;
const CONFIG_HASH: i64 = -4670547;
const CONFIG_DESC: i64 = -4670548;
const AUTHORITY_HASH: i64 = -4670549;
const AUTHORITY_DESC: i64 = -4670550;
const MODE: i64 = -4670551;
const SUBJECT_PUBLIC_KEY: i64 = -4670552;
const KEY_USAGE: i64 = -4670553;

const COMPONENT_NAME: i64 = -70002;
const COMPONENT_VERSION: i64 = -70003;
const RESETTABLE: i64 = -70004;

impl Payload {
    pub(super) fn from_cbor_sign1(
        public_key: Option<&PublicKey>,
        expected_issuer: Option<&str>,
        cbor: Value,
    ) -> Result<Self> {
        let entry = CoseSign1::from_cbor_value(cbor)
            .map_err(cose_error)
            .context("Given CBOR does not appear to be a COSE_sign1")?;
        let payload = payload_from_sign1(public_key, expected_issuer, &entry)
            .context("Unable to extract payload from COSE_sign1")?;
        Ok(payload)
    }
}

/// Validate the protected header of a bcc entry with respect to the provided
/// alg (typically originating from the subject public key of the payload).
fn check_protected_header(alg: &Algorithm, header: &Header) -> Result<()> {
    ensure!(
        header.alg.as_ref() == Some(alg),
        "Protected 'alg' header doesn't have the expected algorithm"
    );
    ensure!(header.crit.is_empty(), "No critical header values may be defined in the BCC");
    Ok(())
}

fn payload_from_sign1(
    pkey: Option<&PublicKey>,
    expected_issuer: Option<&str>,
    sign1: &CoseSign1,
) -> Result<Payload> {
    if let Some(pkey) = pkey {
        check_protected_header(
            &Algorithm::Assigned(pkey.iana_algorithm()),
            &sign1.protected.header,
        )
        .context("Validation of bcc entry protected header failed.")?;
        sign1
            .verify_signature(b"", |s, m| pkey.verify(s, m))
            .context("public key cannot verify cose_sign1 cert")?;
    }

    let bytes = sign1.payload.as_ref().ok_or_else(|| anyhow!("no payload"))?;
    let payload = payload_from_slice(bytes.as_slice())?;
    if let Some(expected_issuer) = expected_issuer {
        ensure!(
            payload.issuer() == expected_issuer,
            "COSE_sign1's issuer ({}) does not match the subject of the previous payload in \
            the chain ({}).",
            payload.issuer(),
            expected_issuer
        );
    }
    Ok(payload)
}

fn payload_from_slice(bytes: &[u8]) -> Result<Payload> {
    let entries = cbor_map_from_slice(bytes)?;

    let mut issuer = FieldValue::new("issuer");
    let mut subject = FieldValue::new("subject");
    let mut subject_public_key = FieldValue::new("subject public key");
    let mut mode = FieldValue::new("mode");
    let mut code_desc = FieldValue::new("code desc");
    let mut code_hash = FieldValue::new("code hash");
    let mut config_desc = FieldValue::new("config desc");
    let mut config_hash = FieldValue::new("config hash");
    let mut authority_desc = FieldValue::new("authority desc");
    let mut authority_hash = FieldValue::new("authority hash");
    let mut key_usage = FieldValue::new("key usage");

    for (key, value) in entries.into_iter() {
        if let Some(Ok(key)) = key.as_integer().map(TryInto::try_into) {
            let field = match key {
                ISS => &mut issuer,
                SUB => &mut subject,
                SUBJECT_PUBLIC_KEY => &mut subject_public_key,
                MODE => &mut mode,
                CODE_DESC => &mut code_desc,
                CODE_HASH => &mut code_hash,
                CONFIG_DESC => &mut config_desc,
                CONFIG_HASH => &mut config_hash,
                AUTHORITY_DESC => &mut authority_desc,
                AUTHORITY_HASH => &mut authority_hash,
                KEY_USAGE => &mut key_usage,
                _ => bail!("Unknown key {}", key),
            };
            field.set(value)?;
        } else {
            bail!("Invalid key: {:?}", key);
        }
    }

    let issuer = issuer.into_string().context("Issuer must be a string")?;
    let subject = subject.into_string().context("Subject must be a string")?;
    let subject_public_key =
        subject_public_key.into_bytes().context("Subject public key must be bytes")?;
    let mode = mode.into_bytes().context("Mode must be bytes")?;
    let code_desc = code_desc.into_optional_bytes().context("Code descriptor must be bytes")?;
    let code_hash = code_hash.into_bytes().context("Code hash must be bytes")?;
    let config_desc = config_desc.into_bytes().context("Config descriptor must be bytes")?;
    let config_hash = config_hash.into_optional_bytes().context("Config hash must be bytes")?;
    let authority_desc =
        authority_desc.into_optional_bytes().context("Authority descriptor must be bytes")?;
    let authority_hash = authority_hash.into_bytes().context("Authority hash must be bytes")?;
    let key_usage = key_usage.into_bytes().context("Key usage must be bytes")?;

    let subject_public_key = CoseKey::from_slice(&subject_public_key)
        .map_err(cose_error)
        .context("Error parsing subject public key from bytes")?;
    let subject_public_key = PublicKey::from_cose_key(&subject_public_key)
        .context("Error parsing subject public key from COSE_key")?;
    if mode.len() != 1 {
        bail!("Expected mode to be a single byte, actual byte count: {}", mode.len())
    };
    let mode = match mode[0] {
        1 => DiceMode::Normal,
        2 => DiceMode::Debug,
        3 => DiceMode::Recovery,
        _ => DiceMode::NotConfigured,
    };

    let config_desc = config_desc_from_slice(&config_desc)
        .context("Error parsing config descriptor from bytes")?;

    if key_usage.len() != 1 || key_usage[0] != 0x20 {
        bail!("key usage must be keyCertSign")
    };

    PayloadBuilder::with_subject_public_key(subject_public_key)
        .issuer(issuer)
        .subject(subject)
        .mode(mode)
        .code_desc(code_desc)
        .code_hash(code_hash)
        .config_desc(config_desc)
        .config_hash(config_hash)
        .authority_desc(authority_desc)
        .authority_hash(authority_hash)
        .build()
        .context("building payload")
}

fn cbor_map_from_slice(bytes: &[u8]) -> Result<Vec<(Value, Value)>> {
    let value = value_from_bytes(bytes).context("Error parsing CBOR into a map")?;
    let entries = match value {
        Value::Map(entries) => entries,
        _ => bail!("Not a map: {:?}", value),
    };
    Ok(entries)
}

fn config_desc_from_slice(bytes: &[u8]) -> Result<ConfigDesc> {
    let entries = cbor_map_from_slice(bytes)?;

    let mut component_name = FieldValue::new("component name");
    let mut component_version = FieldValue::new("component version");
    let mut resettable = FieldValue::new("resettable");
    let mut extensions = HashMap::new();

    for (key, value) in entries.into_iter() {
        if let Some(Ok(key)) = key.as_integer().map(TryInto::try_into) {
            match key {
                COMPONENT_NAME => {
                    component_name.set(value).context("Error setting component name")?
                }
                COMPONENT_VERSION => {
                    component_version.set(value).context("Error setting component version")?
                }
                RESETTABLE => resettable.set(value).context("Error setting resettable")?,
                _ => match extensions.entry(key) {
                    Vacant(entry) => {
                        entry.insert(value);
                    }
                    Occupied(entry) => {
                        bail!("Duplicate values for {}: {:?} and {:?}", key, entry.get(), value)
                    }
                },
            };
        } else {
            bail!("Invalid key: {:?}", key);
        }
    }

    Ok(ConfigDescBuilder::new()
        .component_name(component_name.into_optional_string().context("Component name")?)
        .component_version(component_version.into_optional_i64().context("Component version")?)
        .resettable(resettable.is_null().context("Resettable")?)
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use coset::{iana, Header, Label, RegisteredLabel};

    #[test]
    fn check_bcc_entry_protected_header() -> Result<()> {
        let eddsa = coset::Algorithm::Assigned(iana::Algorithm::EdDSA);
        let header = Header { alg: Some(eddsa.clone()), ..Default::default() };
        check_protected_header(&eddsa, &header).context("Only alg allowed")?;
        let header = Header { alg: Some(coset::Algorithm::PrivateUse(1000)), ..Default::default() };
        assert!(check_protected_header(&eddsa, &header).is_err());
        let mut header = Header { alg: Some(eddsa.clone()), ..Default::default() };
        header.rest.push((Label::Int(1000), Value::from(2000u16)));
        check_protected_header(&eddsa, &header).context("non-crit header allowed")?;
        let mut header = Header { alg: Some(eddsa.clone()), ..Default::default() };
        header.crit.push(RegisteredLabel::Assigned(iana::HeaderParameter::CounterSignature));
        assert!(check_protected_header(&eddsa, &header).is_err());
        Ok(())
    }
}
