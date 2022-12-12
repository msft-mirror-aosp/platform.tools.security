//! The cert validator library provides validation functions for the CBOR-CDDL
//! based certificate request, allowing validation of BCC certificate chain.

pub mod bcc;
pub mod dice;
mod display;
pub mod publickey;

use ciborium::{de::from_reader, value::Value};
use std::io::Read;

type CiboriumError = ciborium::de::Error<std::io::Error>;

/// Reads the provided binary cbor-encoded file and returns a
/// ciborium::Value struct wrapped in Result.
pub fn value_from_file(fname: &str) -> Result<Value, CiboriumError> {
    let bytes = std::fs::read(fname)?;
    value_from_bytes(&bytes)
}

/// Decodes the provided binary CBOR-encoded value and returns a
/// ciborium::Value struct wrapped in Result.
pub fn value_from_bytes(mut bytes: &[u8]) -> Result<Value, CiboriumError> {
    let value = from_reader(bytes.by_ref())?;
    // Ciborium tries to read one Value, but doesn't care if there is trailing data. We do.
    if !bytes.is_empty() {
        return Err(CiboriumError::Semantic(Some(0), "unexpected trailing data".to_string()));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn value_from_bytes_valid_succeeds() -> Result<()> {
        let bytes = [0x82, 0x04, 0x02]; // [4, 2]
        let val = value_from_bytes(&bytes)?;
        let array = val.as_array().unwrap();
        assert_eq!(array.len(), 2);
        Ok(())
    }

    #[test]
    fn value_from_bytes_truncated_fails() {
        let bytes = [0x82, 0x04];
        assert!(value_from_bytes(&bytes).is_err());
    }

    #[test]
    fn value_from_bytes_trailing_bytes_fails() {
        let bytes = [0x82, 0x04, 0x02, 0x00];
        assert!(value_from_bytes(&bytes).is_err());
    }
}
