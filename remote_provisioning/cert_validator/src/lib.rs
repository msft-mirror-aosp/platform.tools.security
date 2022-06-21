//! The cert validator library provides validation functions for the CBOR-CDDL
//! based certificate request, allowing validation of BCC certificate chain,
//! deviceinfo among other things.

pub mod bcc;
pub mod deviceinfo;
pub mod dice;
mod display;
pub mod publickey;
pub mod valueas;

use anyhow::{bail, Context, Result};
use ciborium::{de::from_reader, value::Value};

/// Reads the provided binary cbor-encoded file and returns a
/// ciborium::Value struct wrapped in Result.
pub fn value_from_file(fname: &str) -> Result<Value> {
    let bytes = std::fs::read(fname)?;
    value_from_bytes(&bytes).with_context(|| format!("Decoding {} failed", fname))
}

/// Decodes the provided binary CBOR-encoded value and returns a
/// ciborium::Value struct wrapped in Result.
pub fn value_from_bytes(bytes: &[u8]) -> Result<Value> {
    let mut reader = CheckingReader(bytes);
    let value = from_reader(&mut reader).context("Decoding CBOR failed")?;
    reader.check_no_trailing_data()?;
    Ok(value)
}

/// Wrapper around a slice allowing us to keep ownership (so we can check it has all been
/// consumed) while still implementing the ciborium Read trait.
struct CheckingReader<'a>(&'a [u8]);

impl ciborium_io::Read for &mut CheckingReader<'_> {
    type Error = std::io::Error;

    fn read_exact(&mut self, data: &mut [u8]) -> Result<(), Self::Error> {
        self.0.read_exact(data)
    }
}

impl CheckingReader<'_> {
    fn check_no_trailing_data(&self) -> Result<()> {
        if !self.0.is_empty() {
            bail!("Unexpected trailing data");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use valueas::ValueAs;

    #[test]
    fn value_from_bytes_valid_succeeds() -> Result<()> {
        let bytes = [0x82, 0x04, 0x02]; // [4, 2]
        let val = value_from_bytes(&bytes)?;
        let array = ValueAs::as_array(&val)?;
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
