//! An example binary that uses the libcert_request_validator to accept an
//! array of bcc certificates from the command line and validates that the
//! certificates are valid and that any given cert in the series correctly
//! signs the next.

use anyhow::Result;
use cert_request_validator::bcc;
use clap::{Parser, Subcommand};
use std::fs;

#[derive(Parser)]
/// A tool for handling DICE chains that follow Android's Boot Certificate Chain (BCC)
/// specification.
#[clap(name = "bcc_validator")]
struct Args {
    #[clap(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    VerifyChain(VerifyChainArgs),
}

#[derive(Parser)]
/// Verify that a DICE chain is well formed
struct VerifyChainArgs {
    /// Dump the DICE chain on the standard output
    #[clap(long)]
    dump: bool,

    /// Path to a file containing a DICE chain
    chain: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let Action::VerifyChain(sub_args) = args.action;
    let chain = bcc::Chain::from_bytes(&fs::read(sub_args.chain)?)?;
    println!("Success!");
    if sub_args.dump {
        print!("{}", chain);
    }
    Ok(())
}
