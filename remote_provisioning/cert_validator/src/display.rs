//! Helper functions for implementing Display for our types.

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
