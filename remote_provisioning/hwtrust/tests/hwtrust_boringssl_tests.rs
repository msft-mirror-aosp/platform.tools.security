/// Tests for the usage of BoringSSL in the hwtrust tool.
use anyhow::{anyhow, Result};
use coset::cbor::value::Value;
use coset::iana::{self, EnumI64};
use coset::{CoseKey, CoseKeyBuilder, Label, MlDsaVariant};
use rand::RngCore;

/// Tests that an mldsa65 public key can be generated.
#[test]
fn good_mldsa65_pkey() {
    let mut pubkey = vec![0u8; 1952];
    rand::rng().fill_bytes(&mut pubkey);
    let cose_key = CoseKeyBuilder::new_mldsa_pub_key(MlDsaVariant::MlDsa65, pubkey).build();
    // SAFETY: EVP_pkey_ml_dsa_65 is a constant function.
    let pkey_alg = unsafe { bssl_sys::EVP_pkey_ml_dsa_65() };
    let pub_key =
        get_label_value_as_bytes(&cose_key, Label::Int(iana::AkpKeyParameter::Pub.to_i64()));
    assert!(pub_key.is_ok());
    let pub_key = pub_key.unwrap();
    // SAFETY: pub_key is a valid public key.
    let evp_pkey = unsafe {
        bssl_sys::EVP_PKEY_from_raw_public_key(pkey_alg, pub_key.as_ptr(), pub_key.len())
    };
    assert!(!evp_pkey.is_null());
}

/// Tests that an mldsa87 public key can be generated.
#[test]
fn good_mldsa87_pkey() {
    let mut pubkey = vec![0u8; 2592];
    rand::rng().fill_bytes(&mut pubkey);
    let cose_key = CoseKeyBuilder::new_mldsa_pub_key(MlDsaVariant::MlDsa87, pubkey).build();
    // SAFETY: EVP_pkey_ml_dsa_87 is a constant function.
    let pkey_alg = unsafe { bssl_sys::EVP_pkey_ml_dsa_87() };
    let pub_key =
        get_label_value_as_bytes(&cose_key, Label::Int(iana::AkpKeyParameter::Pub.to_i64()));
    assert!(pub_key.is_ok());
    let pub_key = pub_key.unwrap();
    // SAFETY: pub_key is a valid public key.
    let evp_pkey = unsafe {
        bssl_sys::EVP_PKEY_from_raw_public_key(pkey_alg, pub_key.as_ptr(), pub_key.len())
    };
    assert!(!evp_pkey.is_null());
}

/// Get the byte string for the corresponding label within the key if the label exists and the
/// value is actually a byte array.
fn get_label_value_as_bytes(key: &CoseKey, label: Label) -> Result<&[u8]> {
    get_label_value(key, label)?
        .as_bytes()
        .ok_or_else(|| anyhow!("Value not a bstr."))
        .map(Vec::as_slice)
}

/// Get the value corresponding to the provided label within the supplied CoseKey or error if it's
/// not present.
fn get_label_value(key: &CoseKey, label: Label) -> Result<&Value> {
    Ok(&key
        .params
        .iter()
        .find(|(k, _)| k == &label)
        .ok_or_else(|| anyhow!("Label {:?} not found", label))?
        .1)
}
