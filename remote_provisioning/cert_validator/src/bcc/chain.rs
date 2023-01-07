//! This module provides a wrapper describing a valid Boot Certificate Chain.

use super::entry::Payload;
use crate::publickey::PublicKey;
use anyhow::Result;
use std::fmt::{self, Display, Formatter};

/// Represents a full Boot Certificate Chain (BCC). This consists of the root public key (which
/// signs the first certificate), followed by a chain of BccEntry certificates. Apart from the
/// first, the issuer of each cert is the subject of the previous one.
pub struct Chain {
    root_public_key: PublicKey,
    payloads: Vec<Payload>,
}

impl Chain {
    pub(crate) fn new(root_public_key: PublicKey, payloads: Vec<Payload>) -> Self {
        assert!(!payloads.is_empty());
        Self { root_public_key, payloads }
    }

    /// Get the root public key which verifies the first certificate in the chain.
    pub fn root_public_key(&self) -> &PublicKey {
        &self.root_public_key
    }

    /// Get the payloads of the certificates in the chain, from root to leaf.
    pub fn payloads(&self) -> &[Payload] {
        &self.payloads
    }

    /// Get the payload from the final certificate in the chain.
    pub fn leaf(&self) -> &Payload {
        // There is always at least one payload.
        self.payloads.last().unwrap()
    }
}

impl Display for Chain {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        writeln!(f, "Root public key:")?;
        writeln!(f, "{}", self.root_public_key.to_pem())?;
        for (i, payload) in self.payloads.iter().enumerate() {
            writeln!(f, "Cert {}:", i)?;
            writeln!(f, "{}", payload)?;
        }
        Ok(())
    }
}
