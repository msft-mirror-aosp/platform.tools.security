//! This module wraps the certificate validation functions intended for BccEntry.

use super::field_value::FieldValue;
use super::{cose_error, get_label_value};
use crate::dice;
use crate::display::{write_bytes_field, write_value};
use crate::publickey::PublicKey;
use crate::valueas::ValueAs;
use anyhow::{anyhow, bail, ensure, Context, Result};
use ciborium::value::Value;
use coset::AsCborValue;
use coset::{iana, Algorithm, CborSerializable, CoseKey, CoseSign1, Header, RegisteredLabel};
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::io::Read;

/// Parse a series of BccEntry certificates,represented as CBOR Values, checking the public key of
/// any given cert's payload in the series correctly signs the next, and verifying the payloads
/// are well formed. If root_key is specified then it must be the key used to sign the first (root)
/// certificate; otherwise that signature is not checked.
pub fn check_sign1_chain<T: IntoIterator<Item = Value>>(
    chain: T,
    root_key: Option<&SubjectPublicKey>,
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

    ensure!(!payloads.is_empty());

    Ok(payloads)
}

/// Read a series of bcc file certificates and verify that the public key of
/// any given cert's payload in the series correctly signs the next cose
/// sign1 cert.
pub fn check_sign1_cert_chain(certs: &[&str]) -> Result<()> {
    ensure!(!certs.is_empty());
    let mut payload = RawPayload::from_sign1(&read(certs[0])?)
        .context("Failed to read the first bccEntry payload")?;
    for item in certs.iter().skip(1) {
        payload.check().context("Validation of BccPayload entries failed.")?;
        payload =
            payload.check_sign1(&read(item).context("Failed to read the bccEntry payload")?)?;
    }
    Ok(())
}

/// Read a given cbor array containing bcc entries and verify that the public key
/// of any given cert's payload in the series correctly signs the next cose sign1
/// cert.
pub fn check_sign1_chain_array(cbor_arr: &[Value]) -> Result<()> {
    ensure!(!cbor_arr.is_empty());

    let mut payload = RawPayload::from_sign1(
        &CoseSign1::from_cbor_value(cbor_arr[0].clone()).map_err(cose_error)?,
    )
    .context("Failed to read bccEntry payload")?;
    for item in cbor_arr.iter().skip(1) {
        payload.check().context("Validation of BccPayload entries failed")?;
        let next_sign1 = &CoseSign1::from_cbor_value(item.clone()).map_err(cose_error)?;
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
    pub subject_public_key: SubjectPublicKey,
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
    fn from_cbor_sign1(
        public_key: Option<&SubjectPublicKey>,
        expected_issuer: Option<&str>,
        cbor: Value,
    ) -> Result<Self> {
        let entry = CoseSign1::from_cbor_value(cbor).map_err(cose_error)?;
        let payload = Self::from_sign1(public_key, expected_issuer, &entry)?;
        Ok(payload)
    }

    pub(super) fn from_sign1(
        pkey: Option<&SubjectPublicKey>,
        expected_issuer: Option<&str>,
        sign1: &CoseSign1,
    ) -> Result<Self> {
        if let Some(pkey) = pkey {
            check_protected_header(&pkey.0.alg, &sign1.protected.header)
                .context("Validation of bcc entry protected header failed.")?;
            let v = PublicKey::from_cose_key(&pkey.0)
                .context("Extracting the Public key from coseKey failed.")?;
            sign1.verify_signature(b"", |s, m| v.verify(s, m, &pkey.0.alg)).with_context(|| {
                format!("public key {} incorrectly signs the given cose_sign1 cert.", pkey)
            })?;
        }

        let bytes = sign1.payload.as_ref().ok_or_else(|| anyhow!("no payload"))?;
        let payload = Self::from_slice(bytes.as_slice())?;
        if let Some(expected_issuer) = expected_issuer {
            ensure!(payload.issuer == expected_issuer, "Subject/Issuer mismatch");
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

        let issuer = issuer.into_string()?;
        let subject = subject.into_string()?;
        let subject_public_key = subject_public_key.into_bytes()?;
        let mode = mode.into_bytes()?;
        let code_desc = code_desc.into_optional_bytes()?;
        let code_hash = code_hash.into_bytes()?;
        let config_desc = config_desc.into_bytes()?;
        let config_hash = config_hash.into_optional_bytes()?;
        let authority_desc = authority_desc.into_optional_bytes()?;
        let authority_hash = authority_hash.into_bytes()?;
        let key_usage = key_usage.into_bytes()?;

        let subject_public_key = SubjectPublicKey::from_slice(&subject_public_key)?;
        if mode.len() != 1 {
            bail!("mode must be a single byte")
        };
        let mode = DiceMode::from(mode[0]);

        let config_desc = ConfigDesc::from_slice(&config_desc)?;

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

/// Struct describing BccPayload cbor of the BccEntry.
#[derive(Debug)]
pub struct RawPayload(Value);
impl RawPayload {
    /// Construct the Payload from the parent BccEntry COSE_sign1 structure.
    fn from_sign1(sign1: &CoseSign1) -> Result<RawPayload> {
        let bytes = sign1.payload.as_ref().ok_or_else(|| anyhow!("no payload"))?;
        Self::from_slice(bytes.as_slice())
    }

    /// Validate entries in the Payload to be correct.
    pub(super) fn check(&self) -> Result<()> {
        // Validate required fields.
        self.map_lookup(dice::ISS)?.as_string()?;
        self.map_lookup(dice::SUB)?.as_string()?;
        SubjectPublicKey::from_payload(self)?.check().context("Public key failed checking")?;
        self.map_lookup(dice::KEY_USAGE)?
            .as_bytes()
            .ok_or_else(|| anyhow!("Payload Key usage not bytes"))?;

        // Validate required and optional fields. The required fields are those defined
        // to be present for CDI_Certificates in the open-DICE profile.
        // TODO: Check if the optional fields are present, and if so, ensure that
        //       the operations applied to the mandatory fields actually reproduce the
        //       values in the optional fields as specified in open-DICE.
        self.0.map_lookup(dice::CODE_HASH).context("Code hash must be present.")?;
        self.0.map_lookup(dice::CONFIG_DESC).context("Config descriptor must be present.")?;
        self.0.map_lookup(dice::AUTHORITY_HASH).context("Authority hash must be present.")?;
        self.0.map_lookup(dice::MODE).context("Mode must be present.")?;

        // Verify that each key that does exist has the expected type.
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
    pub(super) fn check_sign1(&self, sign1: &CoseSign1) -> Result<RawPayload> {
        let pkey = SubjectPublicKey::from_payload(self)
            .context("Failed to construct Public key from the Bcc payload.")?;
        let new_payload = Self::check_sign1_signature(&pkey, sign1)?;
        ensure!(
            self.map_lookup(dice::SUB)? == new_payload.map_lookup(dice::ISS)?,
            "Subject/Issuer mismatch"
        );
        Ok(new_payload)
    }

    pub(super) fn check_sign1_signature(
        pkey: &SubjectPublicKey,
        sign1: &CoseSign1,
    ) -> Result<RawPayload> {
        check_protected_header(&pkey.0.alg, &sign1.protected.header)
            .context("Validation of bcc entry protected header failed.")?;
        let v = PublicKey::from_cose_key(&pkey.0)
            .context("Extracting the Public key from coseKey failed.")?;
        sign1.verify_signature(b"", |s, m| v.verify(s, m, &pkey.0.alg)).with_context(|| {
            format!("public key {} incorrectly signs the given cose_sign1 cert.", pkey)
        })?;
        let new_payload = RawPayload::from_sign1(sign1)
            .context("Failed to extract bcc payload from cose_sign1")?;
        Ok(new_payload)
    }

    fn from_slice(b: &[u8]) -> Result<Self> {
        Ok(RawPayload(ciborium::de::from_reader(b).map_err(|e| anyhow!("CborError: {}", e))?))
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

impl Display for SubjectPublicKey {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        let pkey = PublicKey::from_cose_key(&self.0).map_err(|_| fmt::Error)?;
        pkey.fmt(f)
    }
}

impl SubjectPublicKey {
    pub(super) fn from_cose_key(cose_key: CoseKey) -> Self {
        Self(cose_key)
    }

    /// Construct the SubjectPublicKey from the (bccEntry's) Payload.
    pub fn from_payload(payload: &RawPayload) -> Result<SubjectPublicKey> {
        let bytes = payload
            .map_lookup(dice::SUBJECT_PUBLIC_KEY)?
            .as_bytes()
            .ok_or_else(|| anyhow!("public key not bytes"))?;
        Self::from_slice(bytes)
    }

    fn from_slice(bytes: &[u8]) -> Result<SubjectPublicKey> {
        Ok(SubjectPublicKey(CoseKey::from_slice(bytes).map_err(cose_error)?))
    }

    /// Perform validation on the items in the public key.
    pub fn check(&self) -> Result<()> {
        let pkey = &self.0;
        if !pkey.key_ops.is_empty() {
            ensure!(pkey
                .key_ops
                .contains(&coset::KeyOperation::Assigned(iana::KeyOperation::Verify)));
        }
        match pkey.kty {
            coset::KeyType::Assigned(iana::KeyType::OKP) => {
                ensure!(pkey.alg == Some(coset::Algorithm::Assigned(iana::Algorithm::EdDSA)));
                let crv = get_label_value(pkey, iana::OkpKeyParameter::Crv as i64)?;
                ensure!(crv == &Value::from(iana::EllipticCurve::Ed25519 as i64));
            }
            coset::KeyType::Assigned(iana::KeyType::EC2) => {
                ensure!(pkey.alg == Some(coset::Algorithm::Assigned(iana::Algorithm::ES256)));
                let crv = get_label_value(pkey, iana::Ec2KeyParameter::Crv as i64)?;
                ensure!(crv == &Value::from(iana::EllipticCurve::P_256 as i64));
            }
            _ => bail!("Unexpected KeyType value: {:?}", pkey.kty),
        }
        Ok(())
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
                    dice::COMPONENT_NAME => component_name.set(value)?,
                    dice::COMPONENT_VERSION => component_version.set(value)?,
                    dice::RESETTABLE => resettable.set(value)?,
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

        let component_name = component_name.into_optional_string()?;
        let component_version = component_version.into_optional_i64()?;
        let resettable = resettable.is_null()?;

        Ok(Self { component_name, component_version, resettable, extensions })
    }
}

fn cbor_map_from_slice(bytes: &[u8]) -> Result<Vec<(Value, Value)>> {
    let value = ciborium::de::from_reader(bytes).context("Decoding CBOR map failed")?;
    let entries = match value {
        Value::Map(entries) => entries,
        _ => bail!("Not a map: {:?}", value),
    };
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_value;
    use crate::valueas::ValueAs;
    use coset::{iana, Header, Label, RegisteredLabel};

    #[test]
    fn test_bcc_payload_check() {
        let payload = RawPayload::from_sign1(
            &read("testdata/open-dice/_CBOR_Ed25519_cert_full_cert_chain_0.cert").unwrap(),
        );
        assert!(payload.is_ok());

        let payload = payload.unwrap();
        assert!(payload.check().is_ok());
    }

    #[test]
    fn test_bcc_payload_check_sign1() {
        let payload = RawPayload::from_sign1(
            &read("testdata/open-dice/_CBOR_Ed25519_cert_full_cert_chain_0.cert").unwrap(),
        );
        assert!(payload.is_ok(), "Payload not okay: {:?}", payload);
        let payload = payload.unwrap().check_sign1(
            &read("testdata/open-dice/_CBOR_Ed25519_cert_full_cert_chain_1.cert").unwrap(),
        );
        assert!(payload.is_ok(), "Payload not okay: {:?}", payload);
        let payload = payload.unwrap().check_sign1(
            &read("testdata/open-dice/_CBOR_Ed25519_cert_full_cert_chain_2.cert").unwrap(),
        );
        assert!(payload.is_ok(), "Payload not okay: {:?}", payload);
    }

    #[test]
    fn test_check_sign1_cert_chain() {
        let arr: Vec<&str> = vec![
            "testdata/open-dice/_CBOR_Ed25519_cert_full_cert_chain_0.cert",
            "testdata/open-dice/_CBOR_Ed25519_cert_full_cert_chain_1.cert",
            "testdata/open-dice/_CBOR_Ed25519_cert_full_cert_chain_2.cert",
        ];
        assert!(check_sign1_cert_chain(&arr).is_ok());
    }

    #[test]
    fn test_check_sign1_cert_chain_invalid() {
        let arr: Vec<&str> = vec![
            "testdata/open-dice/_CBOR_Ed25519_cert_full_cert_chain_0.cert",
            "testdata/open-dice/_CBOR_Ed25519_cert_full_cert_chain_2.cert",
        ];
        assert!(check_sign1_cert_chain(&arr).is_err());
    }

    #[test]
    fn test_check_sign1_chain_array() {
        let cbor_file = &file_value("testdata/open-dice/_CBOR_bcc_entry_cert_array.cert").unwrap();
        let cbor_arr = ValueAs::as_array(cbor_file).unwrap();
        assert_eq!(cbor_arr.len(), 3);
        assert!(check_sign1_chain_array(cbor_arr).is_ok());
    }

    #[test]
    fn test_check_bcc_entry_protected_header() -> Result<()> {
        let eddsa = Some(coset::Algorithm::Assigned(iana::Algorithm::EdDSA));
        let header = Header { alg: (&eddsa).clone(), ..Default::default() };
        check_protected_header(&eddsa, &header).context("Only alg allowed")?;
        let header = Header { alg: Some(coset::Algorithm::PrivateUse(1000)), ..Default::default() };
        assert!(check_protected_header(&eddsa, &header).is_err());
        let mut header = Header { alg: (&eddsa).clone(), ..Default::default() };
        header.rest.push((Label::Int(1000), Value::from(2000u16)));
        check_protected_header(&eddsa, &header).context("non-crit header allowed")?;
        let mut header = Header { alg: (&eddsa).clone(), ..Default::default() };
        header.crit.push(RegisteredLabel::Assigned(iana::HeaderParameter::Alg));
        check_protected_header(&eddsa, &header).context("OK to say alg is critical")?;
        let mut header = Header { alg: (&eddsa).clone(), ..Default::default() };
        header.crit.push(RegisteredLabel::Assigned(iana::HeaderParameter::CounterSignature));
        assert!(check_protected_header(&eddsa, &header).is_err());
        Ok(())
    }
}
