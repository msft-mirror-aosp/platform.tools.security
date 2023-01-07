//! This module wraps the certificate validation functions intended for BccEntry.

use crate::display::write_bytes_field;
use crate::publickey::PublicKey;
use std::fmt::{self, Display, Formatter};

/// Represents the mode value defined by the Open Profile for DICE. See
/// https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md#mode-value-details.
#[derive(Debug, Copy, Clone)]
#[allow(missing_docs)]
pub enum DiceMode {
    NotConfigured,
    Normal,
    Debug,
    Recovery,
}

/// Represents a decoded BccPayload value.
#[non_exhaustive]
#[allow(missing_docs)]
pub struct Payload {
    pub issuer: String,
    pub subject: String,
    pub subject_public_key: PublicKey,
    pub mode: DiceMode,
    pub code_desc: Option<Vec<u8>>,
    pub code_hash: Vec<u8>,
    pub config_desc: ConfigDesc,
    pub config_hash: Option<Vec<u8>>,
    pub authority_desc: Option<Vec<u8>>,
    pub authority_hash: Vec<u8>,
}

impl Display for Payload {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        writeln!(f, "Issuer: {}", self.issuer)?;
        writeln!(f, "Subject: {}", self.subject)?;
        writeln!(f, "Mode: {:?}", self.mode)?;
        if let Some(code_desc) = &self.code_desc {
            write_bytes_field(f, "Code Desc", code_desc)?;
        }
        write_bytes_field(f, "Code Hash", &self.code_hash)?;
        if let Some(config_hash) = &self.config_hash {
            write_bytes_field(f, "Config Hash", config_hash)?;
        }
        if let Some(authority_desc) = &self.authority_desc {
            write_bytes_field(f, "Authority Desc", authority_desc)?;
        }
        write_bytes_field(f, "Authority Hash", &self.authority_hash)?;
        writeln!(f, "Config Desc:")?;
        write!(f, "{}", &self.config_desc)?;
        Ok(())
    }
}

// Represents a decoded Configuration Descriptor from within a BccPayload.
#[non_exhaustive]
#[allow(missing_docs)]
pub struct ConfigDesc {
    pub component_name: Option<String>,
    pub component_version: Option<i64>,
    pub resettable: bool,
}

impl Display for ConfigDesc {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        if let Some(component_name) = &self.component_name {
            writeln!(f, "Component Name: {}", component_name)?;
        }
        if let Some(component_version) = &self.component_version {
            writeln!(f, "Component Version: {}", component_version)?;
        }
        if self.resettable {
            writeln!(f, "Resettable")?;
        }
        Ok(())
    }
}
