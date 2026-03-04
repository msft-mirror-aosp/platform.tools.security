use crate::dice::Payload;
use crate::publickey::PublicKey;
use crate::session::RkpInstance;
use anyhow::Result;
use std::collections::HashSet;
use std::fmt::{self, Display, Formatter};
use thiserror::Error;

/// The minimum number of RKP VM markers required in a valid [RKP VM DICE chain][rkpvm-chain].
///
/// An RKP VM chain must have a continuous presence of RKP VM markers, starting from a DICE
/// certificate derived in the TEE and extending to the leaf DICE certificate.
/// Therefore, a valid RKP VM chain should have at least two DICE certificates with RKP VM markers:
///
/// * One added in the pVM (managed by Android).
/// * One added in the TEE (managed by vendors).
///
/// [rkpvm-chain]: https://android.googlesource.com/platform/packages/modules/Virtualization/+/main/docs/vm_remote_attestation.md
const RKPVM_CHAIN_MIN_MARKER_NUM: usize = 2;

/// Enumeration of the different forms that a DICE chain can take.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChainForm {
    /// A proper DICE chain with multiple layers of trust.
    Proper(Chain),
    /// A degenerate DICE chain consisting of a single self-signed certificate.
    Degenerate(DegenerateChain),
}

/// Represents a DICE chain. This consists of the root public key (which signs the first
/// certificate), followed by a chain of certificates.
#[derive(Clone, Eq, PartialEq)]
pub struct Chain {
    root_public_key: PublicKey,
    payloads: Vec<Payload>,
}

/// The state of trailing RKP VM markers in a DICE chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrailingRkpVmMarker {
    /// No RKP VM markers were found anywhere in the DICE chain.
    None,
    /// A continuous sequence of RKP VM markers was found that extends
    /// all the way to, and includes, the leaf certificate.
    ///
    /// The associated `usize` value is the number of markers in this
    /// continuous trailing sequence.
    ContinuousToLeaf(usize),
    /// A continuous sequence of RKP VM markers was found, but the
    /// sequence is interrupted by one or more non-marker certificates
    /// at the end of the chain (i.e., the leaf certificate does not have a marker).
    ContinuousNotToLeaf,
}

/// Represents an error that occurred during the structural validation of a DICE chain.
///
/// This error indicates that the chain of certificates is malformed, for example,
/// due to a mismatched issuer/subject link, reuse of a key, or an invalid sequence
/// of RKP VM markers.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum ValidationError {
    #[error("no payloads")]
    NoPayloads,
    #[error("issuer `{1}` is not previous subject `{2}` in payload {0}")]
    IssuerMismatch(usize, String, String),
    #[error("repeated subject in payload {0}")]
    RepeatedSubject(usize, String),
    #[error("repeated key in payload {0}")]
    RepeatedKey(usize),
    #[error("RKP VM chain has discontinuous marker at the {0}th payload")]
    RkpVmChainHasDiscontinuousMarker(usize),
    #[error(
        "For AVF instance: Dice chain does not have enough RKP VM markers. \
         Minimal marker number:{RKPVM_CHAIN_MIN_MARKER_NUM}, actual marker number:{0}"
    )]
    NotEnoughRkpVmMarker(usize),
    #[error(
        "For AVF instance: the sequence of markers must be continuous to the leaf certificate."
    )]
    RkpVmMarkerNotContinuousToLeaf,
}

impl ChainForm {
    pub(crate) fn leaf_public_key(&self) -> &PublicKey {
        match self {
            Self::Proper(chain) => chain.leaf().subject_public_key(),
            Self::Degenerate(degenerate) => degenerate.public_key(),
        }
    }

    /// Return the length of the chain.
    pub fn length(&self) -> usize {
        match self {
            ChainForm::Proper(chain) => chain.payloads.len(),
            ChainForm::Degenerate(_) => 1,
        }
    }
}

impl Chain {
    /// Builds a [`Chain`] after checking that it is well-formed. The issuer of each entry must be
    /// equal to the subject of the previous entry. The chain is not allowed to contain any
    /// repeated subjects or subject public keys as that would suggest something untoward has
    /// happened.
    ///
    /// Additionally, `rkp_instance` provides additional context for the validation of the chain
    /// according to the instance-specific chain validation rules.
    ///
    /// * AVF instance: The chain must have RKP VM markers continuous to the leaf
    ///   certificate with a count of at least RKPVM_CHAIN_MIN_MARKER_NUM.
    /// * Non-AVF instances: RKP VM markers are permitted but not required;
    ///   all marker states (None, ContinuousToLeaf(usize), or ContinuousNotToLeaf) are accepted.
    pub(crate) fn validate(
        root_public_key: PublicKey,
        payloads: Vec<Payload>,
        rkp_instance: RkpInstance,
    ) -> Result<Self, ValidationError> {
        if payloads.is_empty() {
            return Err(ValidationError::NoPayloads);
        }

        let mut subjects = HashSet::with_capacity(payloads.len());
        let mut keys = HashSet::with_capacity(1 + payloads.len());
        keys.insert(root_public_key.to_pem());

        let mut previous_subject: Option<&str> = None;
        for (n, payload) in payloads.iter().enumerate() {
            if let Some(previous_subject) = previous_subject {
                if payload.issuer() != previous_subject {
                    return Err(ValidationError::IssuerMismatch(
                        n,
                        payload.issuer().to_string(),
                        previous_subject.to_string(),
                    ));
                }
            }
            if subjects.replace(payload.subject()).is_some() {
                return Err(ValidationError::RepeatedSubject(n, payload.subject().to_string()));
            }
            if keys.replace(payload.subject_public_key().to_pem()).is_some() {
                return Err(ValidationError::RepeatedKey(n));
            }
            previous_subject = Some(payload.subject());
        }

        let chain = Self { root_public_key, payloads };
        let marker_state = chain.count_trailing_rkp_vm_markers()?;
        if let RkpInstance::Avf = rkp_instance {
            Self::validate_rkp_vm_marker_in_avf_instance(&marker_state)?;
        }
        Ok(chain)
    }

    fn validate_rkp_vm_marker_in_avf_instance(
        marker_state: &TrailingRkpVmMarker,
    ) -> Result<(), ValidationError> {
        match marker_state {
            TrailingRkpVmMarker::ContinuousToLeaf(count) => {
                if *count >= RKPVM_CHAIN_MIN_MARKER_NUM {
                    Ok(())
                } else {
                    Err(ValidationError::NotEnoughRkpVmMarker(*count))
                }
            }

            TrailingRkpVmMarker::None => Err(ValidationError::NotEnoughRkpVmMarker(0)),

            TrailingRkpVmMarker::ContinuousNotToLeaf => {
                Err(ValidationError::RkpVmMarkerNotContinuousToLeaf)
            }
        }
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

    /// Analyzes the RKP VM markers in the DICE chain to determine their trailing state.
    ///
    /// This function checks for a continuous sequence of RKP VM markers at the end of the chain.
    ///
    /// Returns:
    /// * `Ok(TrailingRkpVmMarker::None)`: If no RKP VM markers are found in the chain.
    /// * `Ok(TrailingRkpVmMarker::ContinuousToLeaf(count))`: If there is a continuous sequence
    ///   of `count` RKP VM markers up to and including the leaf certificate.
    /// * `Ok(TrailingRkpVmMarker::ContinuousNotToLeaf)`: If the last marker found is not in the
    ///   leaf certificate (i.e., the sequence breaks before the end).
    /// * `Err(ValidationError::RkpVmChainHasDiscontinuousMarker)`: If a non-marker is found
    ///   *between* RKP VM markers, indicating a broken sequence.
    pub fn count_trailing_rkp_vm_markers(&self) -> Result<TrailingRkpVmMarker, ValidationError> {
        let Some(start_idx) = self.payloads.iter().position(|p| p.has_rkpvm_marker()) else {
            return Ok(TrailingRkpVmMarker::None);
        };

        let mut rkpvm_marker_count = 0;
        let mut last_marker_idx = start_idx;
        let mut seen_non_marker = false;
        for (i, payload) in self.payloads.iter().enumerate().skip(start_idx) {
            if payload.has_rkpvm_marker() {
                if seen_non_marker {
                    return Err(ValidationError::RkpVmChainHasDiscontinuousMarker(i));
                }
                rkpvm_marker_count += 1;
                last_marker_idx = i;
            } else {
                seen_non_marker = true;
            }
        }

        if last_marker_idx == self.payloads.len() - 1 {
            Ok(TrailingRkpVmMarker::ContinuousToLeaf(rkpvm_marker_count))
        } else {
            Ok(TrailingRkpVmMarker::ContinuousNotToLeaf)
        }
    }
}

impl Display for Chain {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        writeln!(f, "Root public key:")?;
        writeln!(f, "{}", self.root_public_key.to_pem())?;
        for (i, payload) in self.payloads.iter().enumerate() {
            writeln!(f, "Cert {i}:")?;
            writeln!(f, "{payload}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Chain {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut debug = fmt.debug_struct("Chain");
        debug.field("Root public key", &self.root_public_key.to_pem());
        for (i, payload) in self.payloads.iter().enumerate() {
            debug.field(&format!("DICE Certificate[{i}]"), payload);
        }
        debug.finish()
    }
}

#[derive(Error, Debug, PartialEq, Eq)]
pub(crate) enum DegenerateChainError {
    #[error("issuer empty")]
    IssuerEmpty,
    #[error("subject empty")]
    SubjectEmpty,
}

/// A degenerate DICE chain. These chains consist of a single, self-signed certificate and the
/// entries contain less information than usual. They are expected from devices that haven't
/// implemented everything necessary to produce a proper DICE Chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DegenerateChain {
    issuer: String,
    subject: String,
    subject_public_key: PublicKey,
}

impl DegenerateChain {
    pub(crate) fn new<I: Into<String>, S: Into<String>>(
        issuer: I,
        subject: S,
        subject_public_key: PublicKey,
    ) -> Result<Self, DegenerateChainError> {
        let issuer = issuer.into();
        let subject = subject.into();
        if issuer.is_empty() {
            return Err(DegenerateChainError::IssuerEmpty);
        }
        if subject.is_empty() {
            return Err(DegenerateChainError::SubjectEmpty);
        }
        Ok(Self { issuer, subject, subject_public_key })
    }

    /// Gets the issuer of the degenerate chain.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Gets the subject of the degenerate chain.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Gets the public key of the degenerate chain.
    pub fn public_key(&self) -> &PublicKey {
        &self.subject_public_key
    }
}

impl Display for DegenerateChain {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        writeln!(f, "Public key:")?;
        writeln!(f, "{}", self.public_key().to_pem())?;
        writeln!(f, "Issuer: {}", self.issuer)?;
        writeln!(f, "Subject: {}", self.subject)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dice::{ConfigDescBuilder, DiceMode, PayloadBuilder};
    use crate::publickey::testkeys::{PrivateKey, ED25519_KEY_PEM, P256_KEY_PEM, P384_KEY_PEM};

    #[test]
    fn chain_validate_valid() {
        let root_public_key = PrivateKey::from_pem(P256_KEY_PEM[0]).public_key();
        let keys = P256_KEY_PEM[1..4].iter().copied().enumerate();
        let payloads = keys.map(|(n, key)| valid_payload(n, key).build().unwrap()).collect();
        Chain::validate(root_public_key, payloads, RkpInstance::Default).unwrap();
    }

    #[test]
    fn chain_validate_valid_with_mixed_kinds_of_key() {
        let root_public_key = PrivateKey::from_pem(ED25519_KEY_PEM[0]).public_key();
        let keys = [P256_KEY_PEM[0], P384_KEY_PEM[0]].into_iter().enumerate();
        let payloads = keys.map(|(n, key)| valid_payload(n, key).build().unwrap()).collect();
        Chain::validate(root_public_key, payloads, RkpInstance::Default).unwrap();
    }

    #[test]
    fn chain_validate_fails_without_payloads() {
        let root_public_key = PrivateKey::from_pem(P256_KEY_PEM[0]).public_key();
        let payloads = Vec::new();
        let err = Chain::validate(root_public_key, payloads, RkpInstance::Default).unwrap_err();
        assert_eq!(err, ValidationError::NoPayloads);
    }

    #[test]
    fn chain_validate_fails_when_root_key_repeated() {
        let key = P256_KEY_PEM[0];
        let root_public_key = PrivateKey::from_pem(key).public_key();
        let payloads = vec![valid_payload(0, key).build().unwrap()];
        let err = Chain::validate(root_public_key, payloads, RkpInstance::Default).unwrap_err();
        assert_eq!(err, ValidationError::RepeatedKey(0));
    }

    #[test]
    fn chain_validate_fails_with_repeated_subject_public_keys() {
        let repeated_key = P256_KEY_PEM[0];
        let root_public_key = PrivateKey::from_pem(ED25519_KEY_PEM[0]).public_key();
        let payloads = vec![
            valid_payload(0, repeated_key).build().unwrap(),
            valid_payload(1, repeated_key).build().unwrap(),
        ];
        let err = Chain::validate(root_public_key, payloads, RkpInstance::Default).unwrap_err();
        assert_eq!(err, ValidationError::RepeatedKey(1));
    }

    #[test]
    fn chain_validate_fails_with_repeated_subjects() {
        let keys = &P256_KEY_PEM[..3];
        let repeated = "match";
        let root_public_key = PrivateKey::from_pem(ED25519_KEY_PEM[0]).public_key();
        let payloads = vec![
            valid_payload(0, keys[0]).subject(repeated).build().unwrap(),
            valid_payload(1, keys[1]).issuer(repeated).build().unwrap(),
            valid_payload(2, keys[2]).subject(repeated).build().unwrap(),
        ];
        let err = Chain::validate(root_public_key, payloads, RkpInstance::Default).unwrap_err();
        assert_eq!(err, ValidationError::RepeatedSubject(2, repeated.into()));
    }

    #[test]
    fn chain_validate_fails_with_mismatching_issuer_and_subject() {
        let expected = "expected";
        let wrong = "wrong";
        let root_public_key = PrivateKey::from_pem(P256_KEY_PEM[0]).public_key();
        let payloads = vec![
            valid_payload(0, P256_KEY_PEM[1]).subject(expected).build().unwrap(),
            valid_payload(1, P256_KEY_PEM[2]).issuer(wrong).build().unwrap(),
        ];
        let err = Chain::validate(root_public_key, payloads, RkpInstance::Default).unwrap_err();
        assert_eq!(err, ValidationError::IssuerMismatch(1, wrong.into(), expected.into()));
    }

    #[test]
    fn non_rkpvm_chain_validate_with_discontinuous_markers() {
        let root_public_key = PrivateKey::from_pem(P256_KEY_PEM[0]).public_key();
        let config_desc = ConfigDescBuilder::new().rkp_vm_marker(true).build();
        // This chain resembles a Microdroid pVM DICE chain where vendors add RKP VM markers in
        // the vendor part of the chain, while pVM does not.
        let payloads = vec![
            valid_payload(0, P256_KEY_PEM[1]).build().unwrap(),
            valid_payload(1, P256_KEY_PEM[2]).config_desc(config_desc.clone()).build().unwrap(),
            valid_payload(2, P256_KEY_PEM[3]).build().unwrap(),
        ];
        Chain::validate(root_public_key, payloads, RkpInstance::Default).unwrap();
    }

    #[test]
    fn non_rkpvm_chain_validate_succeeds_with_continuous_markers() {
        let root_public_key = PrivateKey::from_pem(P256_KEY_PEM[0]).public_key();
        let config_desc = ConfigDescBuilder::new().rkp_vm_marker(true).build();
        let payloads = vec![
            valid_payload(0, P256_KEY_PEM[1]).build().unwrap(),
            valid_payload(1, P256_KEY_PEM[2]).config_desc(config_desc.clone()).build().unwrap(),
            valid_payload(2, P256_KEY_PEM[3]).config_desc(config_desc.clone()).build().unwrap(),
        ];
        Chain::validate(root_public_key, payloads, RkpInstance::Default).unwrap();
    }

    #[test]
    fn rkpvm_chain_validate_with_continuous_markers() {
        let root_public_key = PrivateKey::from_pem(P256_KEY_PEM[0]).public_key();
        let config_desc = ConfigDescBuilder::new().rkp_vm_marker(true).build();
        let payloads = vec![
            valid_payload(0, P256_KEY_PEM[1]).build().unwrap(),
            valid_payload(1, P256_KEY_PEM[2]).config_desc(config_desc.clone()).build().unwrap(),
            valid_payload(2, P256_KEY_PEM[3]).config_desc(config_desc.clone()).build().unwrap(),
        ];
        Chain::validate(root_public_key, payloads, RkpInstance::Avf).unwrap();
    }

    #[test]
    fn rkpvm_chain_validate_fails_with_no_marker() {
        let root_public_key = PrivateKey::from_pem(P256_KEY_PEM[0]).public_key();
        let payloads = vec![valid_payload(0, P256_KEY_PEM[1]).build().unwrap()];
        let err = Chain::validate(root_public_key, payloads, RkpInstance::Avf).unwrap_err();
        assert_eq!(err, ValidationError::NotEnoughRkpVmMarker(0));
    }

    #[test]
    fn rkpvm_chain_validate_fails_with_not_enough_markers() {
        let root_public_key = PrivateKey::from_pem(P256_KEY_PEM[0]).public_key();
        let config_desc = ConfigDescBuilder::new().rkp_vm_marker(true).build();
        let payloads = vec![
            valid_payload(0, P256_KEY_PEM[1]).build().unwrap(),
            valid_payload(1, P256_KEY_PEM[2]).config_desc(config_desc).build().unwrap(),
        ];
        let err = Chain::validate(root_public_key, payloads, RkpInstance::Avf).unwrap_err();
        assert_eq!(err, ValidationError::NotEnoughRkpVmMarker(1));
    }

    #[test]
    fn rkpvm_chain_validate_fails_with_discontinous_markers() {
        let root_public_key = PrivateKey::from_pem(P256_KEY_PEM[0]).public_key();
        let config_desc = ConfigDescBuilder::new().rkp_vm_marker(true).build();
        let payloads = vec![
            valid_payload(0, P256_KEY_PEM[1]).config_desc(config_desc.clone()).build().unwrap(),
            valid_payload(1, P256_KEY_PEM[2]).build().unwrap(),
            valid_payload(2, P256_KEY_PEM[3]).config_desc(config_desc.clone()).build().unwrap(),
        ];
        let err = Chain::validate(root_public_key, payloads, RkpInstance::Avf).unwrap_err();
        assert_eq!(err, ValidationError::RkpVmChainHasDiscontinuousMarker(2));
    }

    #[test]
    fn rkpvm_chain_validate_fails_last_payload_has_no_marker() {
        let root_public_key = PrivateKey::from_pem(P256_KEY_PEM[0]).public_key();
        let config_desc = ConfigDescBuilder::new().rkp_vm_marker(true).build();
        let payloads = vec![
            valid_payload(0, P256_KEY_PEM[1]).config_desc(config_desc.clone()).build().unwrap(),
            valid_payload(1, P256_KEY_PEM[2]).config_desc(config_desc.clone()).build().unwrap(),
            valid_payload(2, P256_KEY_PEM[3]).build().unwrap(),
        ];
        let err = Chain::validate(root_public_key, payloads, RkpInstance::Avf).unwrap_err();
        assert_eq!(err, ValidationError::RkpVmMarkerNotContinuousToLeaf);
    }

    #[test]
    fn count_trailing_markers_returns_zero_with_no_markers_at_all() {
        let root_public_key = PrivateKey::from_pem(P256_KEY_PEM[0]).public_key();
        let config_no_marker = ConfigDescBuilder::new().rkp_vm_marker(false).build();

        let payloads = vec![
            valid_payload(0, P256_KEY_PEM[1])
                .config_desc(config_no_marker.clone())
                .build()
                .unwrap(),
            valid_payload(1, P256_KEY_PEM[2])
                .config_desc(config_no_marker.clone())
                .build()
                .unwrap(),
        ];
        let chain = Chain::validate(root_public_key, payloads, RkpInstance::Default).unwrap();
        assert_eq!(chain.count_trailing_rkp_vm_markers().unwrap(), TrailingRkpVmMarker::None);
    }

    #[test]
    fn count_trailing_markers_returns_error_for_discontinuous_chain() {
        let root_public_key = PrivateKey::from_pem(P256_KEY_PEM[0]).public_key();
        let config_with_marker = ConfigDescBuilder::new().rkp_vm_marker(true).build();
        let config_no_marker = ConfigDescBuilder::new().rkp_vm_marker(false).build();

        let payloads = vec![
            valid_payload(0, P256_KEY_PEM[1])
                .config_desc(config_with_marker.clone())
                .build()
                .unwrap(),
            valid_payload(1, P256_KEY_PEM[2])
                .config_desc(config_no_marker.clone())
                .build()
                .unwrap(),
            valid_payload(2, P256_KEY_PEM[3])
                .config_desc(config_with_marker.clone())
                .build()
                .unwrap(),
        ];
        let result = Chain::validate(root_public_key, payloads, RkpInstance::Default);
        assert_eq!(result.unwrap_err(), ValidationError::RkpVmChainHasDiscontinuousMarker(2));
    }

    #[test]
    fn count_trailing_markers_succeeds_with_non_marker_at_end() {
        let root_public_key = PrivateKey::from_pem(P256_KEY_PEM[0]).public_key();
        let config_with_marker = ConfigDescBuilder::new().rkp_vm_marker(true).build();
        let config_no_marker = ConfigDescBuilder::new().rkp_vm_marker(false).build();

        let payloads = vec![
            valid_payload(0, P256_KEY_PEM[1])
                .config_desc(config_with_marker.clone())
                .build()
                .unwrap(),
            valid_payload(1, P256_KEY_PEM[2])
                .config_desc(config_with_marker.clone())
                .build()
                .unwrap(),
            valid_payload(2, P256_KEY_PEM[3])
                .config_desc(config_no_marker.clone())
                .build()
                .unwrap(),
        ];
        let chain = Chain::validate(root_public_key, payloads, RkpInstance::Default).unwrap();
        assert_eq!(
            chain.count_trailing_rkp_vm_markers().unwrap(),
            TrailingRkpVmMarker::ContinuousNotToLeaf
        );
    }

    #[test]
    fn count_trailing_markers_succeeds_with_trailing_sequence() {
        let root_public_key = PrivateKey::from_pem(P256_KEY_PEM[0]).public_key();
        let config_with_marker = ConfigDescBuilder::new().rkp_vm_marker(true).build();
        let config_no_marker = ConfigDescBuilder::new().rkp_vm_marker(false).build();

        let payloads = vec![
            valid_payload(0, P256_KEY_PEM[1])
                .config_desc(config_no_marker.clone())
                .build()
                .unwrap(),
            valid_payload(1, P256_KEY_PEM[2])
                .config_desc(config_with_marker.clone())
                .build()
                .unwrap(),
            valid_payload(2, P256_KEY_PEM[3])
                .config_desc(config_with_marker.clone())
                .build()
                .unwrap(),
        ];
        let chain = Chain::validate(root_public_key, payloads, RkpInstance::Avf).unwrap();
        assert_eq!(
            chain.count_trailing_rkp_vm_markers().unwrap(),
            TrailingRkpVmMarker::ContinuousToLeaf(2)
        );
    }

    #[test]
    fn count_trailing_markers_succeeds_with_all_markers() {
        let root_public_key = PrivateKey::from_pem(P256_KEY_PEM[0]).public_key();
        let config_with_marker = ConfigDescBuilder::new().rkp_vm_marker(true).build();

        let payloads = vec![
            valid_payload(0, P256_KEY_PEM[1])
                .config_desc(config_with_marker.clone())
                .build()
                .unwrap(),
            valid_payload(1, P256_KEY_PEM[2])
                .config_desc(config_with_marker.clone())
                .build()
                .unwrap(),
            valid_payload(2, P256_KEY_PEM[3])
                .config_desc(config_with_marker.clone())
                .build()
                .unwrap(),
        ];
        let chain = Chain::validate(root_public_key, payloads, RkpInstance::Avf).unwrap();
        assert_eq!(
            chain.count_trailing_rkp_vm_markers().unwrap(),
            TrailingRkpVmMarker::ContinuousToLeaf(3)
        );
    }

    fn valid_payload(index: usize, pem: &str) -> PayloadBuilder {
        PayloadBuilder::with_subject_public_key(PrivateKey::from_pem(pem).public_key())
            .issuer(format!("component {index}"))
            .subject(format!("component {}", index + 1))
            .mode(DiceMode::Normal)
            .code_hash(vec![0; 64])
            .authority_hash(vec![0; 64])
    }

    #[test]
    fn degenerate_chain_valid() {
        let key = PrivateKey::from_pem(ED25519_KEY_PEM[0]).public_key();
        DegenerateChain::new("issuer", "issuer", key).unwrap();
    }

    #[test]
    fn degenerate_chain_empty_issuer() {
        let key = PrivateKey::from_pem(ED25519_KEY_PEM[0]).public_key();
        let err = DegenerateChain::new("", "subject", key).unwrap_err();
        assert_eq!(err, DegenerateChainError::IssuerEmpty);
    }

    #[test]
    fn degenerate_chain_empty_subject() {
        let key = PrivateKey::from_pem(ED25519_KEY_PEM[0]).public_key();
        let err = DegenerateChain::new("issuer", "", key).unwrap_err();
        assert_eq!(err, DegenerateChainError::SubjectEmpty);
    }
}
