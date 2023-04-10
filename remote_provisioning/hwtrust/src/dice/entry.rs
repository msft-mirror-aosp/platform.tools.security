use crate::publickey::PublicKey;
use std::fmt::{self, Display, Formatter};
use thiserror::Error;

/// Enumeration of modes used in the DICE chain payloads.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub enum DiceMode {
    /// This mode also acts as a catch-all for configurations which do not fit the other modes and
    /// invalid modes.
    #[default]
    NotConfigured,
    /// The device is operating normally under secure configuration.
    Normal,
    /// At least one criteria for [`Normal`] is not met and the device is not in a secure state.
    Debug,
    /// A recovery or maintenance mode of some kind.
    Recovery,
}

/// The payload of a DICE chain entry.
#[derive(Debug)]
pub struct Payload {
    issuer: String,
    subject: String,
    subject_public_key: PublicKey,
    mode: DiceMode,
    code_desc: Option<Vec<u8>>,
    code_hash: Vec<u8>,
    config_desc: ConfigDesc,
    config_hash: Option<Vec<u8>>,
    authority_desc: Option<Vec<u8>>,
    authority_hash: Vec<u8>,
}

impl Payload {
    /// Gets the issuer of the payload.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Gets the subject of the payload.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Gets the subject public key of the payload.
    pub fn subject_public_key(&self) -> &PublicKey {
        &self.subject_public_key
    }

    /// Gets the mode of the payload.
    pub fn mode(&self) -> DiceMode {
        self.mode
    }

    /// Gets the code descriptor of the payload.
    pub fn code_desc(&self) -> Option<&[u8]> {
        self.code_desc.as_deref()
    }

    /// Gets the code hash of the payload.
    pub fn code_hash(&self) -> &[u8] {
        &self.code_hash
    }

    /// Gets the configuration descriptor of the payload.
    pub fn config_desc(&self) -> &ConfigDesc {
        &self.config_desc
    }

    /// Gets the configuration hash of the payload.
    pub fn config_hash(&self) -> Option<&[u8]> {
        self.config_hash.as_deref()
    }

    /// Gets the authority descriptor of the payload.
    pub fn authority_desc(&self) -> Option<&[u8]> {
        self.authority_desc.as_deref()
    }

    /// Gets the authority hash of the payload.
    pub fn authority_hash(&self) -> &[u8] {
        &self.authority_hash
    }
}

impl Display for Payload {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        writeln!(f, "Issuer: {}", self.issuer)?;
        writeln!(f, "Subject: {}", self.subject)?;
        writeln!(f, "Mode: {:?}", self.mode)?;
        if let Some(code_desc) = &self.code_desc {
            writeln!(f, "Code Desc: {}", hex::encode(code_desc))?;
        }
        writeln!(f, "Code Hash: {}", hex::encode(&self.code_hash))?;
        if let Some(config_hash) = &self.config_hash {
            writeln!(f, "Config Hash: {}", hex::encode(config_hash))?;
        }
        if let Some(authority_desc) = &self.authority_desc {
            writeln!(f, "Authority Desc: {}", hex::encode(authority_desc))?;
        }
        writeln!(f, "Authority Hash: {}", hex::encode(&self.authority_hash))?;
        writeln!(f, "Config Desc:")?;
        write!(f, "{}", &self.config_desc)?;
        Ok(())
    }
}

#[derive(Error, Debug, PartialEq, Eq)]
pub(crate) enum PayloadBuilderError {
    #[error("issuer empty")]
    IssuerEmpty,
    #[error("subject empty")]
    SubjectEmpty,
    #[error("bad code hash size")]
    CodeHashSize,
    #[error("bad config hash size")]
    ConfigHashSize,
    #[error("bad authority hash size")]
    AuthorityHashSize,
}

pub(crate) struct PayloadBuilder(Payload);

impl PayloadBuilder {
    /// Constructs a new builder with the given subject public key.
    pub fn with_subject_public_key(subject_public_key: PublicKey) -> Self {
        Self(Payload {
            issuer: Default::default(),
            subject: Default::default(),
            subject_public_key,
            mode: Default::default(),
            code_desc: Default::default(),
            code_hash: Default::default(),
            config_desc: Default::default(),
            config_hash: Default::default(),
            authority_desc: Default::default(),
            authority_hash: Default::default(),
        })
    }

    /// Builds the [`Payload`] after validating the fields.
    pub fn build(self) -> Result<Payload, PayloadBuilderError> {
        if self.0.issuer.is_empty() {
            return Err(PayloadBuilderError::IssuerEmpty);
        }
        if self.0.subject.is_empty() {
            return Err(PayloadBuilderError::SubjectEmpty);
        }
        let used_hash_size = self.0.code_hash.len();
        if ![32, 48, 64].contains(&used_hash_size) {
            return Err(PayloadBuilderError::CodeHashSize);
        }
        if let Some(ref config_hash) = self.0.config_hash {
            if config_hash.len() != used_hash_size {
                return Err(PayloadBuilderError::ConfigHashSize);
            }
        }
        if self.0.authority_hash.len() != used_hash_size {
            return Err(PayloadBuilderError::AuthorityHashSize);
        }
        Ok(self.0)
    }

    /// Sets the issuer of the payload.
    #[must_use]
    pub fn issuer<S: Into<String>>(mut self, issuer: S) -> Self {
        self.0.issuer = issuer.into();
        self
    }

    /// Sets the subject of the payload.
    #[must_use]
    pub fn subject<S: Into<String>>(mut self, subject: S) -> Self {
        self.0.subject = subject.into();
        self
    }

    /// Sets the mode of the payload.
    #[must_use]
    pub fn mode(mut self, mode: DiceMode) -> Self {
        self.0.mode = mode;
        self
    }

    /// Sets the code descriptor of the payload.
    #[must_use]
    pub fn code_desc(mut self, code_desc: Option<Vec<u8>>) -> Self {
        self.0.code_desc = code_desc;
        self
    }

    /// Sets the code hash of the payload.
    #[must_use]
    pub fn code_hash(mut self, code_hash: Vec<u8>) -> Self {
        self.0.code_hash = code_hash;
        self
    }

    /// Sets the configuration descriptor of the payload.
    #[must_use]
    pub fn config_desc(mut self, config_desc: ConfigDesc) -> Self {
        self.0.config_desc = config_desc;
        self
    }

    /// Sets the configuration hash of the payload.
    #[must_use]
    pub fn config_hash(mut self, config_hash: Option<Vec<u8>>) -> Self {
        self.0.config_hash = config_hash;
        self
    }

    /// Sets the authority descriptor of the payload.
    #[must_use]
    pub fn authority_desc(mut self, authority_desc: Option<Vec<u8>>) -> Self {
        self.0.authority_desc = authority_desc;
        self
    }

    /// Sets the authority hash of the payload.
    #[must_use]
    pub fn authority_hash(mut self, authority_hash: Vec<u8>) -> Self {
        self.0.authority_hash = authority_hash;
        self
    }
}

/// Fields from the configuration descriptor.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConfigDesc {
    component_name: Option<String>,
    component_version: Option<i64>,
    resettable: bool,
}

impl ConfigDesc {
    /// Gets the component name.
    pub fn component_name(&self) -> Option<&str> {
        self.component_name.as_deref()
    }

    /// Gets the component version.
    pub fn component_version(&self) -> Option<i64> {
        self.component_version
    }

    /// Returns whether the component is factory resettable.
    pub fn resettable(&self) -> bool {
        self.resettable
    }
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

pub(crate) struct ConfigDescBuilder(ConfigDesc);

impl ConfigDescBuilder {
    /// Constructs a new builder with default values.
    pub fn new() -> Self {
        Self(ConfigDesc::default())
    }

    /// Builds the [`ConfigDesc`].
    pub fn build(self) -> ConfigDesc {
        self.0
    }

    /// Sets the component name.
    #[must_use]
    pub fn component_name(mut self, name: Option<String>) -> Self {
        self.0.component_name = name;
        self
    }

    /// Sets the component version.
    #[must_use]
    pub fn component_version(mut self, version: Option<i64>) -> Self {
        self.0.component_version = version;
        self
    }

    /// Sets whether the component is factory resettable.
    #[must_use]
    pub fn resettable(mut self, resettable: bool) -> Self {
        self.0.resettable = resettable;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publickey::testkeys::{PrivateKey, P256_KEY_PEM};

    #[test]
    fn payload_builder_valid() {
        valid_payload().build().unwrap();
    }

    #[test]
    fn payload_builder_valid_512_bit_hashes() {
        valid_payload()
            .code_hash(vec![1; 64])
            .authority_hash(vec![2; 64])
            .config_hash(Some(vec![3; 64]))
            .build()
            .unwrap();
    }

    #[test]
    fn payload_builder_valid_384_bit_hashes() {
        valid_payload()
            .code_hash(vec![1; 48])
            .authority_hash(vec![2; 48])
            .config_hash(Some(vec![3; 48]))
            .build()
            .unwrap();
    }

    #[test]
    fn payload_builder_valid_256_bit_hashes() {
        valid_payload()
            .code_hash(vec![1; 32])
            .authority_hash(vec![2; 32])
            .config_hash(Some(vec![3; 32]))
            .build()
            .unwrap();
    }

    #[test]
    fn payload_builder_empty_issuer() {
        let err = valid_payload().issuer("").build().unwrap_err();
        assert_eq!(err, PayloadBuilderError::IssuerEmpty);
    }

    #[test]
    fn payload_builder_empty_subject() {
        let err = valid_payload().subject("").build().unwrap_err();
        assert_eq!(err, PayloadBuilderError::SubjectEmpty);
    }

    #[test]
    fn payload_builder_bad_code_hash_size() {
        let err = valid_payload().code_hash(vec![1; 16]).build().unwrap_err();
        assert_eq!(err, PayloadBuilderError::CodeHashSize);
    }

    #[test]
    fn payload_builder_bad_authority_hash_size() {
        let err = valid_payload().authority_hash(vec![1; 16]).build().unwrap_err();
        assert_eq!(err, PayloadBuilderError::AuthorityHashSize);
    }

    #[test]
    fn payload_builder_inconsistent_authority_hash_size() {
        let err =
            valid_payload().code_hash(vec![1; 32]).authority_hash(vec![1; 64]).build().unwrap_err();
        assert_eq!(err, PayloadBuilderError::AuthorityHashSize);
    }

    #[test]
    fn payload_builder_bad_config_hash_size() {
        let err = valid_payload().config_hash(Some(vec![1; 16])).build().unwrap_err();
        assert_eq!(err, PayloadBuilderError::ConfigHashSize);
    }

    #[test]
    fn payload_builder_inconsistent_config_hash_size() {
        let err = valid_payload()
            .code_hash(vec![1; 64])
            .config_hash(Some(vec![1; 32]))
            .build()
            .unwrap_err();
        assert_eq!(err, PayloadBuilderError::ConfigHashSize);
    }

    fn valid_payload() -> PayloadBuilder {
        let key = PrivateKey::from_pem(P256_KEY_PEM[0]).public_key();
        PayloadBuilder::with_subject_public_key(key)
            .issuer("issuer")
            .subject("subject")
            .code_hash(vec![1; 64])
            .authority_hash(vec![2; 64])
    }
}
