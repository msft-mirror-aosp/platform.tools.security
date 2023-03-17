//! Defines the context type for a session handling hwtrust data structures.

/// The context for a session handling hwtrust data structures.
pub struct Session {
    /// Options that control the behaviour during this session.
    pub options: Options,
}

/// Options that control the behaviour of a session.
#[derive(Default)]
pub struct Options {
    /// The expected format for the configuration descriptor in the first certificate of the DICE
    /// chain. When the chain is ROM-rooted, the first certificate is generated by ROM so this
    /// option can be used for compatibility with ROMs.
    pub first_dice_chain_cert_config_format: ConfigFormat,

    /// The types that are permitted for the key_ops field of COSE_Key objects in the DICE chain.
    /// This option can be used for compatibility with the RKP HAL before v3 which diverged from
    /// the COSE spec and allowed a single int instead of always requiring an array.
    pub dice_chain_key_ops_type: KeyOpsType,
}

/// Format of the DICE configuration descriptor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ConfigFormat {
    /// The configuration descriptor format specified by Android.
    #[default]
    Android,
    /// Any configuration descriptor format is allowed.
    Permissive,
}

/// Type allowed for the COSE_Key object key_ops field in the DICE chain.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KeyOpsType {
    /// The key_ops field must be an array as specified in the COSE RFC.
    #[default]
    Array,
    /// The key_ops field can be either a single int or an array as specified in the COSE RFC.
    IntOrArray,
}