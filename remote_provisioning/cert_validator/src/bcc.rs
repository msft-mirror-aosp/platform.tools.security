//! This module provides functions for validating chains of bcc certificates

mod chain;
pub mod entry;
mod field_value;

use anyhow::anyhow;
pub use chain::Chain;

fn cose_error(ce: coset::CoseError) -> anyhow::Error {
    anyhow!("CoseError: {:?}", ce)
}
