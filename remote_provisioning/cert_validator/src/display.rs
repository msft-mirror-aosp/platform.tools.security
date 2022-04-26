//! Helper functions for implementing Display for our types.

use crate::valueas::ValueAs;
use coset::cbor::value::Value;
use std::fmt::{self, Formatter};

pub fn write_bytes_in_hex(f: &mut Formatter, bytes: &[u8]) -> Result<(), fmt::Error> {
    for b in bytes {
        write!(f, "{:02x}", b)?
    }
    Ok(())
}

pub fn write_value(f: &mut Formatter, value: &Value) -> Result<(), fmt::Error> {
    if let Some(bytes) = value.as_bytes() {
        write_bytes_in_hex(f, bytes)
    } else if let Some(text) = value.as_text() {
        write!(f, "\"{}\"", text)
    } else if let Ok(integer) = value.as_i64() {
        write!(f, "{}", integer)
    } else {
        write!(f, "{:?}", value)
    }
}
