//! A tool for handling data related to the hardware root-of-trust.

use anyhow::{bail, Result};
use clap::{Parser, Subcommand, ValueEnum};
use hwtrust::dice;
use hwtrust::rkp;
use hwtrust::session::{Options, Session};
use std::io::BufRead;
use std::{fs, io};

#[derive(Parser)]
/// A tool for handling data related to the hardware root-of-trust
#[clap(name = "hwtrust")]
struct Args {
    #[clap(subcommand)]
    action: Action,

    /// Verbose output, including parsed data structures.
    #[clap(long)]
    verbose: bool,

    /// The VSR version to validate against. If omitted, the set of rules that are used have no
    /// compromises or workarounds and new implementations should validate against them as it will
    /// be the basis for future VSR versions.
    #[clap(long, value_enum)]
    vsr: Option<VsrVersion>,
}

#[derive(Subcommand)]
enum Action {
    DiceChain(DiceChainArgs),
    FactoryCsr(FactoryCsrArgs),
}

#[derive(Parser)]
/// Verify that a DICE chain is well-formed
///
/// DICE chains are expected to follow the specification of the RKP HAL [1] which is based on the
/// Open Profile for DICE [2].
///
/// [1] -- https://cs.android.com/android/platform/superproject/+/master:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/IRemotelyProvisionedComponent.aidl
/// [2] -- https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md
struct DiceChainArgs {
    /// Path to a file containing a DICE chain
    chain: String,
}

#[derive(Parser)]
/// Parse and verify a CSR, as gnerated by the rkp_factory_extraction_tool. "v1" CSRs are also
/// decrypted using the factory EEK.
struct FactoryCsrArgs {
    /// Path to a file containing one or more CSRs, in the "csr+json" format as defined by
    /// rkp_factory_extraction_tool. Each line is interpreted as a separate JSON blob containing
    /// a base64-encoded CSR.
    csr_file: String,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum VsrVersion {
    /// VSR 13 / Android T / 2022
    Vsr13,
    /// VSR 14 / Android U / 2023
    Vsr14,
    /// VSR 15 / Android V / 2024
    Vsr15,
    /// VSR 16 / Android W / 2025
    Vsr16,
}

fn session_from_vsr(vsr: Option<VsrVersion>) -> Session {
    Session {
        options: match vsr {
            Some(VsrVersion::Vsr13) => Options::vsr13(),
            Some(VsrVersion::Vsr14) => Options::vsr14(),
            Some(VsrVersion::Vsr15) => Options::vsr15(),
            Some(VsrVersion::Vsr16) => {
                println!();
                println!();
                println!("  ********************************************************************");
                println!("  ! The selected VSR is not finalized and is subject to change.      !");
                println!("  ! Please contact your TAM if you intend to depend on the           !");
                println!("  ! validation rules use for the selected VSR.                       !");
                println!("  ********************************************************************");
                println!();
                println!();
                Options::vsr16()
            }
            None => Options::default(),
        },
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    match &args.action {
        Action::DiceChain(sub_args) => verify_dice_chain(&args, sub_args)?,
        Action::FactoryCsr(sub_args) => parse_factory_csr(&args, sub_args)?,
    }
    println!("Success!");
    Ok(())
}

fn verify_dice_chain(args: &Args, sub_args: &DiceChainArgs) -> Result<()> {
    let session = session_from_vsr(args.vsr);
    let chain = dice::Chain::from_cbor(&session, &fs::read(&sub_args.chain)?)?;
    if args.verbose {
        print!("{}", chain);
    }
    Ok(())
}

fn parse_factory_csr(args: &Args, sub_args: &FactoryCsrArgs) -> Result<()> {
    let session = session_from_vsr(args.vsr);
    let input = &fs::File::open(&sub_args.csr_file)?;
    let mut csr_count = 0;
    for line in io::BufReader::new(input).lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        let csr = rkp::FactoryCsr::from_json(&session, &line)?;
        csr_count += 1;
        if args.verbose {
            println!("{csr_count}: {csr:#?}");
        }
    }
    if csr_count == 0 {
        bail!("No CSRs found in the input file '{}'", sub_args.csr_file);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn verify_command() {
        Args::command().debug_assert();
    }
}
