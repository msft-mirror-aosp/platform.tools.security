//! An example binary that uses the libcert_request_validator to accept an
//! array of bcc certificates from the command line and validates that the
//! certificates are valid and that any given cert in the series correctly
//! signs the next.

use anyhow::{bail, Result};
use cert_request_validator::bcc;
use clap::{Arg, SubCommand};
use std::fs;

fn main() -> Result<()> {
    let mut app = clap::Command::new("bcc_validator")
        .subcommand(
            SubCommand::with_name("verify-chain")
                .arg(Arg::with_name("dump").long("dump"))
                .arg(Arg::with_name("chain")),
        )
        .subcommand(
            SubCommand::with_name("verify-certs")
                .arg(Arg::with_name("dump").long("dump"))
                .arg(Arg::with_name("certs").multiple(true).min_values(1)),
        );

    let usage = app.render_usage();

    let args = app.get_matches();
    match args.subcommand() {
        Some(("verify-chain", sub_args)) => {
            if let Some(chain) = sub_args.value_of("chain") {
                let chain = bcc::Chain::from_bytes(&fs::read(chain)?)?;
                if sub_args.is_present("dump") {
                    print!("{}", chain);
                }
                return Ok(());
            }
        }
        Some(("verify-certs", sub_args)) => {
            if let Some(certs) = sub_args.values_of("certs") {
                let certs: Vec<_> = certs.collect();
                let payloads = bcc::entry::check_sign1_cert_chain(&certs)?;
                if sub_args.is_present("dump") {
                    for (i, payload) in payloads.iter().enumerate() {
                        println!("Cert {}:", i);
                        println!("{}", payload);
                    }
                }
                return Ok(());
            }
        }
        _ => {}
    }
    eprintln!("{}", usage);
    bail!("Invalid arguments");
}
