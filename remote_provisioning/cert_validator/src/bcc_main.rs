//! An example binary that uses the libcert_request_validator to accept an
//! array of bcc certificates from the command line and validates that the
//! certificates are valid and that any given cert in the series correctly
//! signs the next.

pub mod bcc;
pub mod deviceinfo;
pub mod dice;
pub mod publickey;
pub mod valueas;

use std::env;

use anyhow::{ensure, Result};

fn main() -> Result<()> {
    ensure!(env::args().len() > 1, "Provide at least one bcc certificate file");

    let mut arr: Vec<String> = Vec::new();
    for item in env::args().skip(1) {
        arr.push(item.to_string());
    }
    bcc::entry::check_sign1_cert_chain(&arr)
}