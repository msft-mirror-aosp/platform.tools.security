//! This module wraps the certificate validation functions intended for BccEntry.

use super::cose_error;
use super::field_value::FieldValue;
use crate::dice;
use crate::display::{write_bytes_field, write_value};
use crate::publickey::PublicKey;
use crate::value_from_bytes;
use crate::valueas::ValueAs;
use anyhow::{anyhow, bail, ensure, Context, Result};
use ciborium::value::Value;
use coset::AsCborValue;
use coset::{Algorithm, CborSerializable, CoseKey, CoseSign1, Header};
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};

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

/// Represents the mode value defined by the Open Profile for DICE. See
/// https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md#mode-value-details.
#[repr(u8)]
#[derive(Debug, Copy, Clone)]
#[allow(missing_docs)]
pub enum DiceMode {
    NotConfigured = 0,
    Normal = 1,
    Debug = 2,
    Recovery = 3,
}

impl From<u8> for DiceMode {
    fn from(byte: u8) -> Self {
        // You can match against a constant, but not an expression.
        const NORMAL: u8 = DiceMode::Normal as u8;
        const DEBUG: u8 = DiceMode::Debug as u8;
        const RECOVERY: u8 = DiceMode::Recovery as u8;

        match byte {
            NORMAL => Self::Normal,
            DEBUG => Self::Debug,
            RECOVERY => Self::Recovery,
            _ => Self::NotConfigured, // open-dice says to treat unknown values as this
        }
    }
}

/// Represents a decoded BccPayload value.
#[non_exhaustive]
#[allow(missing_docs)]
pub struct Payload {
    pub issuer: String,
    pub subject: String,
    pub subject_public_key: PublicKey,
    pub mode: DiceMode,
    pub code_desc: Option<Vec<u8>>,
    pub code_hash: Vec<u8>,
    pub config_desc: ConfigDesc,
    pub config_hash: Option<Vec<u8>>,
    pub authority_desc: Option<Vec<u8>>,
    pub authority_hash: Vec<u8>,
}

impl Display for Payload {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        writeln!(f, "Issuer: {}", self.issuer)?;
        writeln!(f, "Subject: {}", self.subject)?;
        writeln!(f, "Mode: {:?}", self.mode)?;
        if let Some(code_desc) = &self.code_desc {
            write_bytes_field(f, "Code Desc", code_desc)?;
        }
        write_bytes_field(f, "Code Hash", &self.code_hash)?;
        if let Some(config_hash) = &self.config_hash {
            write_bytes_field(f, "Config Hash", config_hash)?;
        }
        if let Some(authority_desc) = &self.authority_desc {
            write_bytes_field(f, "Authority Desc", authority_desc)?;
        }
        write_bytes_field(f, "Authority Hash", &self.authority_hash)?;
        writeln!(f, "Config Desc:")?;
        write!(f, "{}", &self.config_desc)?;
        Ok(())
    }
}

impl Payload {
    pub(super) fn from_cbor_sign1(
        public_key: Option<&PublicKey>,
        expected_issuer: Option<&str>,
        cbor: Value,
    ) -> Result<Self> {
        let entry = CoseSign1::from_cbor_value(cbor)
            .map_err(cose_error)
            .context("Given CBOR does not appear to be a COSE_sign1")?;
        let payload = Self::from_sign1(public_key, expected_issuer, &entry)
            .context("Unable to extract payload from COSE_sign1")?;
        Ok(payload)
    }

    pub(super) fn from_sign1(
        pkey: Option<&PublicKey>,
        expected_issuer: Option<&str>,
        sign1: &CoseSign1,
    ) -> Result<Self> {
        if let Some(pkey) = pkey {
            check_protected_header(&pkey.algorithm(), &sign1.protected.header)
                .context("Validation of bcc entry protected header failed.")?;
            sign1.verify_signature(b"", |s, m| pkey.verify(s, m)).with_context(|| {
                format!("public key {} incorrectly signs the given cose_sign1 cert.", pkey)
            })?;
        }

        let bytes = sign1.payload.as_ref().ok_or_else(|| anyhow!("no payload"))?;
        let payload = Self::from_slice(bytes.as_slice())?;
        if let Some(expected_issuer) = expected_issuer {
            ensure!(
                payload.issuer == expected_issuer,
                "COSE_sign1's issuer ({}) does not match the subject of the previous payload in \
                the chain ({}).",
                payload.issuer,
                expected_issuer
            );
        }
        Ok(payload)
    }

    fn from_slice(bytes: &[u8]) -> Result<Self> {
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
            if let Ok(key) = key.as_i64() {
                let field = match key {
                    dice::ISS => &mut issuer,
                    dice::SUB => &mut subject,
                    dice::SUBJECT_PUBLIC_KEY => &mut subject_public_key,
                    dice::MODE => &mut mode,
                    dice::CODE_DESC => &mut code_desc,
                    dice::CODE_HASH => &mut code_hash,
                    dice::CONFIG_DESC => &mut config_desc,
                    dice::CONFIG_HASH => &mut config_hash,
                    dice::AUTHORITY_DESC => &mut authority_desc,
                    dice::AUTHORITY_HASH => &mut authority_hash,
                    dice::KEY_USAGE => &mut key_usage,
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
        let mode = DiceMode::from(mode[0]);

        let config_desc = ConfigDesc::from_slice(&config_desc)
            .context("Error parsing config descriptor from bytes")?;

        if key_usage.len() != 1 || key_usage[0] != 0x20 {
            bail!("key usage must be keyCertSign")
        };

        Ok(Self {
            issuer,
            subject,
            subject_public_key,
            mode,
            code_desc,
            code_hash,
            config_desc,
            config_hash,
            authority_desc,
            authority_hash,
        })
    }
}

// Represents a decoded Configuration Descriptor from within a BccPayload.
#[non_exhaustive]
#[allow(missing_docs)]
pub struct ConfigDesc {
    pub component_name: Option<String>,
    pub component_version: Option<i64>,
    pub resettable: bool,
    extensions: HashMap<i64, Value>, // TODO: Figure out how to expose this
}

impl Display for ConfigDesc {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        if let Some(component_name) = &self.component_name {
            writeln!(f, "Component Name: {}", component_name)?;
        }
        if let Some(component_version) = &self.component_version {
            writeln!(f, "Component Version: {}", component_version)?;
        }
        if self.resettable {
            writeln!(f, "Resettable")?;
        }
        for (key, value) in self.extensions.iter() {
            write!(f, "{}: ", key)?;
            write_value(f, value)?;
            writeln!(f)?;
        }
        Ok(())
    }
}

impl ConfigDesc {
    fn from_slice(bytes: &[u8]) -> Result<Self> {
        let entries = cbor_map_from_slice(bytes)?;

        let mut component_name = FieldValue::new("component name");
        let mut component_version = FieldValue::new("component version");
        let mut resettable = FieldValue::new("resettable");
        let mut extensions = HashMap::new();

        for (key, value) in entries.into_iter() {
            if let Ok(key) = key.as_i64() {
                match key {
                    dice::COMPONENT_NAME => {
                        component_name.set(value).context("Error setting component name")?
                    }
                    dice::COMPONENT_VERSION => {
                        component_version.set(value).context("Error setting component version")?
                    }
                    dice::RESETTABLE => {
                        resettable.set(value).context("Error setting resettable")?
                    }
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

        let component_name =
            component_name.into_optional_string().context("Component name must be a string")?;
        let component_version = component_version
            .into_optional_i64()
            .context("Component version must be an integer")?;
        let resettable = resettable.is_null().context("Error interpreting resettable field")?;

        Ok(Self { component_name, component_version, resettable, extensions })
    }
}

fn cbor_map_from_slice(bytes: &[u8]) -> Result<Vec<(Value, Value)>> {
    let value = value_from_bytes(bytes).context("Error parsing CBOR into a map")?;
    let entries = match value {
        Value::Map(entries) => entries,
        _ => bail!("Not a map: {:?}", value),
    };
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use coset::{iana, Header, Label, RegisteredLabel};

    #[test]
    fn test_check_bcc_entry_protected_header() -> Result<()> {
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
