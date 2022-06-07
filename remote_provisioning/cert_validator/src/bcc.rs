//! This module provides functions for validating chains of bcc certificates

mod chain;
pub mod entry;
mod field_value;

use anyhow::{anyhow, Result};
pub use chain::Chain;
use coset::cbor::value::Value;

fn cose_error(ce: coset::CoseError) -> anyhow::Error {
    anyhow!("CoseError: {:?}", ce)
}

/// Get the value corresponding to the provided label within the supplied CoseKey
/// or error if it's not present.
pub fn get_label_value(key: &coset::CoseKey, label: i64) -> Result<&Value> {
    Ok(&key
        .params
        .iter()
        .find(|(k, _)| k == &coset::Label::Int(label))
        .ok_or_else(|| anyhow!("Label {:?} not found", label))?
        .1)
}

/// Get the byte string for the corresponding label within the key if the label exists
/// and the value is actually a byte array.
pub fn get_label_value_as_bytes(key: &coset::CoseKey, label: i64) -> Result<&Vec<u8>> {
    get_label_value(key, label)?.as_bytes().ok_or_else(|| anyhow!("Value not a bstr."))
}
