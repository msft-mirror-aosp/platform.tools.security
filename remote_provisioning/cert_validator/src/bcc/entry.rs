//! This module wraps the certificate validation functions intended for BccEntry.

use super::{cose_error, get_label_value};
use crate::dice;
use crate::display::write_value;
use crate::publickey::PublicKey;
use crate::valueas::ValueAs;
use anyhow::{anyhow, bail, ensure, Context, Result};
use coset::AsCborValue;
use coset::{
    cbor::value::Value,
    iana, Algorithm, CborSerializable,
    CoseError::{self, EncodeFailed, UnexpectedItem},
    CoseKey, CoseSign1, Header, RegisteredLabel,
};
use std::fmt::{self, Display, Formatter, Write};
use std::io::Read;

/// Read a series of bcc file certificates and verify that the public key of
/// any given cert's payload in the series correctly signs the next cose
/// sign1 cert.
pub fn check_sign1_cert_chain(certs: &[&str]) -> Result<()> {
    ensure!(!certs.is_empty());
    let mut payload = Payload::from_sign1(&read(certs[0])?)
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

    let mut writeme: Vec<u8> = Vec::new();
    ciborium::ser::into_writer(&cbor_arr[0], &mut writeme)?;
    let mut payload = Payload::from_sign1(&CoseSign1::from_slice(&writeme).map_err(cose_error)?)
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
/// Struct describing BccPayload cbor of the BccEntry.
#[derive(Debug)]
pub struct Payload(Value);
impl Payload {
    /// Construct the Payload from the parent BccEntry COSE_sign1 structure.
    fn from_sign1(sign1: &CoseSign1) -> Result<Payload> {
        Self::from_slice(sign1.payload.as_ref().ok_or_else(|| anyhow!("no payload"))?)
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
    pub(super) fn check_sign1(&self, sign1: &CoseSign1) -> Result<Payload> {
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
    ) -> Result<Payload> {
        check_protected_header(&pkey.0.alg, &sign1.protected.header)
            .context("Validation of bcc entry protected header failed.")?;
        let v = PublicKey::from_cose_key(&pkey.0)
            .context("Extracting the Public key from coseKey failed.")?;
        sign1.verify_signature(b"", |s, m| v.verify(s, m, &pkey.0.alg)).with_context(|| {
            format!("public key {} incorrectly signs the given cose_sign1 cert.", pkey)
        })?;
        let new_payload =
            Payload::from_sign1(sign1).context("Failed to extract bcc payload from cose_sign1")?;
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
    pub(super) fn from_cose_key(cose_key: CoseKey) -> Self {
        Self(cose_key)
    }

    /// Construct the SubjectPublicKey from the (bccEntry's) Payload.
    pub fn from_payload(payload: &Payload) -> Result<SubjectPublicKey> {
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

struct ConfigDesc(Vec<(Value, Value)>);

impl AsCborValue for ConfigDesc {
    /*
     * CDDL (from keymint/ProtectedData.aidl):
     *
     *  bstr .cbor {      // Configuration Descriptor
     *     ? -70002 : tstr,           // Component name
     *     ? -70003 : int,            // Firmware version
     *     ? -70004 : null,           // Resettable
     * },
     */

    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
        match value {
            Value::Map(m) => Ok(Self(m)),
            _ => Err(UnexpectedItem("something", "a map")),
        }
    }

    fn to_cbor_value(self) -> Result<Value, CoseError> {
        // TODO: Implement when needed
        Err(EncodeFailed)
    }
}

impl CborSerializable for ConfigDesc {}

impl Display for ConfigDesc {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write_payload_label(f, dice::CONFIG_DESC)?;
        f.write_str(":\n")?;
        for (label, value) in &self.0 {
            f.write_str("  ")?;
            if let Ok(i) = label.as_i64() {
                write_config_desc_label(f, i)?;
            } else {
                write_value(f, label)?;
            }
            f.write_str(": ")?;
            write_value(f, value)?;
            f.write_char('\n')?;
        }
        Ok(())
    }
}

fn write_config_desc_label(f: &mut Formatter, label: i64) -> Result<(), fmt::Error> {
    match label {
        dice::COMPONENT_NAME => f.write_str("Component Name"),
        dice::FIRMWARE_VERSION => f.write_str("Firmware Version"),
        dice::RESETTABLE => f.write_str("Resettable"),
        _ => label.fmt(f),
    }
}

impl Display for SubjectPublicKey {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        let pkey = PublicKey::from_cose_key(&self.0).map_err(|_| fmt::Error)?;
        pkey.fmt(f)
    }
}

impl Display for Payload {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        for (label, value) in self.0.as_map().ok_or(fmt::Error)? {
            if let Ok(i) = label.as_i64() {
                if i == dice::CONFIG_DESC {
                    write_config_desc(f, value)?;
                    continue;
                } else if i == dice::SUBJECT_PUBLIC_KEY {
                    write_payload_label(f, i)?;
                    f.write_str(": ")?;
                    write_subject_public_key(f, value)?;
                    continue;
                }
                write_payload_label(f, i)?;
            } else {
                write_value(f, label)?;
            }
            f.write_str(": ")?;
            write_value(f, value)?;
            f.write_char('\n')?;
        }
        Ok(())
    }
}

fn write_payload_label(f: &mut Formatter, label: i64) -> Result<(), fmt::Error> {
    match label {
        dice::ISS => f.write_str("Issuer"),
        dice::SUB => f.write_str("Subject"),
        dice::CODE_HASH => f.write_str("Code Hash"),
        dice::CODE_DESC => f.write_str("Code Desc"),
        dice::CONFIG_DESC => f.write_str("Config Desc"),
        dice::CONFIG_HASH => f.write_str("Config Hash"),
        dice::AUTHORITY_HASH => f.write_str("Authority Hash"),
        dice::AUTHORITY_DESC => f.write_str("Authority Desc"),
        dice::MODE => f.write_str("Mode"),
        dice::SUBJECT_PUBLIC_KEY => f.write_str("Subject Public Key"),
        dice::KEY_USAGE => f.write_str("Key Usage"),
        _ => label.fmt(f),
    }
}

fn write_config_desc(f: &mut Formatter, value: &Value) -> Result<(), fmt::Error> {
    let bytes = value.as_bytes().ok_or(fmt::Error)?;
    let config_desc = ConfigDesc::from_slice(bytes).map_err(|_| fmt::Error)?;
    config_desc.fmt(f)
}

fn write_subject_public_key(f: &mut Formatter, value: &Value) -> Result<(), fmt::Error> {
    let bytes = value.as_bytes().ok_or(fmt::Error)?;
    let subject_public_key = SubjectPublicKey::from_slice(bytes).map_err(|_| fmt::Error)?;
    writeln!(f, "{}", subject_public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_value;
    use crate::valueas::ValueAs;
    use coset::{iana, Header, Label, RegisteredLabel};

    #[test]
    fn test_bcc_payload_check() {
        let payload = Payload::from_sign1(
            &read("testdata/open-dice/_CBOR_Ed25519_cert_full_cert_chain_0.cert").unwrap(),
        );
        assert!(payload.is_ok());

        let payload = payload.unwrap();
        assert!(payload.check().is_ok());
    }

    #[test]
    fn test_bcc_payload_check_sign1() {
        let payload = Payload::from_sign1(
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
