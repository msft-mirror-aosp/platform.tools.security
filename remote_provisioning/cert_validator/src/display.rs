//! Helper functions for implementing Display for our types.

use coset::cbor::value::Value;
use std::fmt::{self, Formatter};

pub fn write_bytes_in_hex(f: &mut Formatter, bytes: &[u8]) -> Result<(), fmt::Error> {
    for b in bytes {
        write!(f, "{:02x}", b)?
    }
    Ok(())
}

pub fn write_bytes_field(f: &mut Formatter, name: &str, value: &[u8]) -> Result<(), fmt::Error> {
    write!(f, "{}: ", name)?;
    write_bytes_in_hex(f, value)?;
    writeln!(f)
}

pub fn write_value(f: &mut Formatter, value: &Value) -> Result<(), fmt::Error> {
    if let Some(bytes) = value.as_bytes() {
        write_bytes_in_hex(f, bytes)
    } else if let Some(text) = value.as_text() {
        write!(f, "\"{}\"", text)
    } else if let Some(Ok(integer)) = value.as_integer().map(TryInto::<i64>::try_into) {
        write!(f, "{}", integer)
    } else {
        write!(f, "{:?}", value)
    }
}
