//! An example binary that uses the libcert_request_validator to accept an
//! array of bcc certificates from the command line and validates that the
//! certificates are valid and that any given cert in the series correctly
//! signs the next.

use anyhow::{bail, Result};
use cert_request_validator::bcc;
use clap::{Arg, SubCommand};
use std::fs;

fn main() -> Result<()> {
    let mut app = clap::Command::new("bcc_validator").subcommand(
        SubCommand::with_name("verify-chain")
            .arg(Arg::with_name("dump").long("dump"))
            .arg(Arg::with_name("chain")),
    );

    let usage = app.render_usage();

    let args = app.get_matches();
    if let Some(("verify-chain", sub_args)) = args.subcommand() {
        if let Some(chain) = sub_args.value_of("chain") {
            let chain = bcc::Chain::from_bytes(&fs::read(chain)?)?;
            println!("Success!");
            if sub_args.is_present("dump") {
                print!("{}", chain);
            }
            return Ok(());
        }
    }
    eprintln!("{}", usage);
    bail!("Invalid arguments");
}
