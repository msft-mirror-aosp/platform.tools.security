//! An example binary that uses the libcert_request_validator to accept an
//! array of bcc certificates from the command line and validates that the
//! certificates are valid and that any given cert in the series correctly
//! signs the next.

use anyhow::{bail, Result};
use cert_request_validator::bcc;
use clap::{Arg, SubCommand};

fn main() -> Result<()> {
    let app = clap::App::new("bcc_validator")
        .subcommand(SubCommand::with_name("verify-chain").arg(Arg::with_name("chain")))
        .subcommand(
            SubCommand::with_name("verify-certs")
                .arg(Arg::with_name("certs").multiple(true).min_values(1)),
        );

    let args = app.get_matches();
    match args.subcommand() {
        ("verify-chain", Some(sub_args)) => {
            if let Some(chain) = sub_args.value_of("chain") {
                return bcc::Chain::read(chain)?.check();
            }
        }
        ("verify-certs", Some(sub_args)) => {
            if let Some(certs) = sub_args.values_of("certs") {
                let certs: Vec<_> = certs.collect();
                return bcc::entry::check_sign1_cert_chain(&certs);
            }
        }
        _ => {}
    }
    eprintln!("{}", args.usage());
    bail!("Invalid arguments");
}
