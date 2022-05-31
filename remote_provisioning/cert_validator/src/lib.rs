//! The cert validator library provides validation functions for the CBOR-CDDL
//! based certificate request, allowing validation of BCC certificate chain,
//! deviceinfo among other things.

pub mod bcc;
pub mod deviceinfo;
pub mod dice;
mod display;
pub mod publickey;
pub mod valueas;

use anyhow::{Context, Result};
use ciborium::{de::from_reader, value::Value};

/// Reads the provided binary cbor-encoded file and returns a
/// ciborium::Value struct wrapped in Result.
pub fn file_value(fname: &str) -> Result<Value> {
    let f = std::fs::File::open(fname)?;
    from_reader(f).with_context(|| format!("Decoding {}", fname))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deviceinfo_validation() {
        let val = &file_value("testdata/device-info/_CBOR_device_info_0.cert").unwrap();
        let deviceinfo = deviceinfo::extract(val);
        assert!(deviceinfo.is_ok());
        assert!(deviceinfo::check(deviceinfo.unwrap()).is_ok());
    }
}
