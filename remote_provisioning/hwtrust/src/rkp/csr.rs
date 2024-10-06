use std::{collections::HashMap, fmt};

use openssl::x509::X509;

use crate::{dice::ChainForm, rkp::DeviceInfo};

use super::ProtectedData;

/// Represents a Certificate Signing Request that is sent to an RKP backend to request
/// certificates to be signed for a set of public keys. The CSR is partially generated by an
/// IRemotelyProvisionedComponent HAL. The set of public keys to be signed is authenticated
/// (signed) with a device-unique key.
#[derive(Clone, Eq, PartialEq)]
pub enum Csr {
    /// CSR V2 was introduced in Android T. In this version, the payload is encrypted using
    /// an Endpoint Encryption Key (EEK).
    V2 {
        /// Describes the device that is requesting certificates.
        device_info: DeviceInfo,
        /// This is the challenge that is authenticated inside the protected data.
        challenge: Vec<u8>,
        /// Contains the plaintext of the payload that was encrypted to an EEK.
        protected_data: ProtectedData,
    },
    /// CSR V3 was introduced in Android T. This version drops encryption of the payload.
    V3 {
        /// Describes the device that is requesting certificates.
        device_info: DeviceInfo,
        /// The DICE chain for the device
        dice_chain: ChainForm,
        /// X.509 certificate chain that certifies the dice_chain root key (UDS_pub)
        uds_certs: HashMap<String, Vec<X509>>,
    },
}

impl fmt::Debug for Csr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Csr::V2 { device_info, challenge, protected_data } => fmt
                .debug_struct("CSR V2")
                .field("DeviceInfo", &device_info)
                .field("Challenge", &hex::encode(challenge))
                .field("ProtectedData", &protected_data)
                .finish(),
            Csr::V3 { device_info, dice_chain, uds_certs } => fmt
                .debug_struct("CSR V3")
                .field("DeviceInfo", &device_info)
                .field("DiceChain", &dice_chain)
                .field("UdsCerts", &uds_certs)
                .finish(),
        }
    }
}
