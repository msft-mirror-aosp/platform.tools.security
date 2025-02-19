use coset::CoseKey;
use openssl::x509::X509;
use std::{collections::HashMap, fmt};
use thiserror::Error;

use crate::dice::ChainForm;

use super::{DeviceInfo, ProtectedData, UdsCerts};

/// Represents the keys to sign that are to be signed
#[derive(Clone, Debug, PartialEq)]
pub struct KeysToSign(pub Vec<CoseKey>);

/// Represents the payload of a Certificate Signing Request
#[derive(Clone, PartialEq)]
pub struct CsrPayload {
    /// The original serialized CSR payload
    pub serialized: Vec<u8>,
    /// RKP VM or other?
    pub certificate_type: String,
    /// Describes the device that is requesting certificates.
    pub device_info: DeviceInfo,
    /// The keys to attest to when doing key attestation in one buffer
    pub keys_to_sign: KeysToSign,
}

/// Represents a Certificate Signing Request that is sent to an RKP backend to request
/// certificates to be signed for a set of public keys. The CSR is partially generated by an
/// IRemotelyProvisionedComponent HAL. The set of public keys to be signed is authenticated
/// (signed) with a device-unique key.
#[derive(Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
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
    /// CSR V3 was introduced in Android U. This version drops encryption of the payload.
    V3 {
        /// The DICE chain for the device
        dice_chain: ChainForm,
        /// X.509 certificate chain that certifies the dice_chain root key (UDS_pub)
        uds_certs: HashMap<String, Vec<X509>>,
        /// The challenge that is authenticated inside the signed data.
        challenge: Vec<u8>,
        /// The payload of the signed data.
        csr_payload: CsrPayload,
    },
}

impl Csr {
    /// copy the DICE chain and return it
    pub fn dice_chain(&self) -> ChainForm {
        match self {
            Csr::V2 { protected_data, .. } => protected_data.dice_chain(),
            Csr::V3 { dice_chain, .. } => dice_chain.clone(),
        }
    }

    /// copy the UDS certs map and return it
    pub fn has_uds_certs(&self) -> bool {
        match self {
            Csr::V2 { protected_data, .. } => match protected_data.uds_certs() {
                Some(uds_certs) => match uds_certs {
                    UdsCerts(map) => !map.is_empty(),
                },
                None => false,
            },
            Csr::V3 { uds_certs, .. } => !uds_certs.is_empty(),
        }
    }

    /// copy the challenge and return it
    pub fn challenge(&self) -> Vec<u8> {
        match self {
            Csr::V2 { challenge, .. } => challenge.clone(),
            Csr::V3 { challenge, .. } => challenge.clone(),
        }
    }

    /// copy the serialized CSR payload and return it
    pub fn csr_payload(&self) -> Vec<u8> {
        match self {
            Csr::V2 { .. } => Vec::new(),
            Csr::V3 { csr_payload, .. } => csr_payload.serialized.clone(),
        }
    }

    /// copy the device info and return it
    pub fn compare_keys_to_sign(&self, keys_to_sign: &[u8]) -> bool {
        let keys_to_sign = match KeysToSign::from_bytes(keys_to_sign) {
            Ok(keys_to_sign) => keys_to_sign,
            Err(_) => return false,
        };

        match self {
            Csr::V2 { .. } => false,
            Csr::V3 { csr_payload, .. } => csr_payload.keys_to_sign == keys_to_sign,
        }
    }
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
            Csr::V3 { dice_chain, uds_certs, csr_payload, .. } => fmt
                .debug_struct("CSR V3")
                .field("DeviceInfo", &csr_payload.device_info)
                .field("DiceChain", &dice_chain)
                .field("UdsCerts", &uds_certs)
                .finish(),
        }
    }
}

/// Builder errors for Csr V2 and V3.
#[derive(Debug, PartialEq, Error)]
pub enum CsrBuilderError {
    /// Device info is missing.
    #[error("Missing device info")]
    MissingDeviceInfo,
    /// Challenge is missing.
    #[error("Missing challenge")]
    MissingChallenge,
    /// Protected data is missing.
    #[error("Missing protected data")]
    MissingProtectedData,
    /// DICE chain is missing.
    #[error("Missing DICE chain")]
    MissingDiceChain,
    /// CSR payload is missing.
    #[error("Missing CSR payload")]
    MissingCsrPayload,
    /// UDS certificates are missing.
    #[error("Missing UDS certificates")]
    MissingUdsCerts,
}

/// Builder for Csr::V2.
#[derive(Default)]
pub struct CsrV2Builder {
    device_info: Option<DeviceInfo>,
    challenge: Option<Vec<u8>>,
    protected_data: Option<ProtectedData>,
}

impl CsrV2Builder {
    /// Builds the CSR V2.
    pub fn build(self) -> Result<Csr, CsrBuilderError> {
        let device_info = self.device_info.ok_or(CsrBuilderError::MissingDeviceInfo)?;
        let challenge = self.challenge.ok_or(CsrBuilderError::MissingChallenge)?;
        let protected_data = self.protected_data.ok_or(CsrBuilderError::MissingProtectedData)?;

        Ok(Csr::V2 { device_info, challenge, protected_data })
    }

    /// Sets the device info.
    #[must_use]
    pub fn device_info(mut self, device_info: DeviceInfo) -> Self {
        self.device_info = Some(device_info);
        self
    }

    /// Sets the challenge.
    #[must_use]
    pub fn challenge(mut self, challenge: Vec<u8>) -> Self {
        self.challenge = Some(challenge);
        self
    }

    /// Sets the protected data.
    #[must_use]
    pub fn protected_data(mut self, protected_data: ProtectedData) -> Self {
        self.protected_data = Some(protected_data);
        self
    }
}

/// Builder for Csr::V3.
#[derive(Default)]
pub struct CsrV3Builder {
    challenge: Option<Vec<u8>>,
    dice_chain: Option<ChainForm>,
    uds_certs: Option<HashMap<String, Vec<X509>>>,
    csr_payload: Option<CsrPayload>,
}

impl CsrV3Builder {
    /// Builds Csr::V3.
    pub fn build(self) -> Result<Csr, CsrBuilderError> {
        let challenge = self.challenge.ok_or(CsrBuilderError::MissingChallenge)?;
        let dice_chain = self.dice_chain.ok_or(CsrBuilderError::MissingDiceChain)?;
        let uds_certs = self.uds_certs.ok_or(CsrBuilderError::MissingUdsCerts)?;
        let csr_payload = self.csr_payload.ok_or(CsrBuilderError::MissingCsrPayload)?;

        Ok(Csr::V3 { dice_chain, uds_certs, challenge, csr_payload })
    }

    /// Sets the challenge.
    #[must_use]
    pub fn challenge(mut self, challenge: Vec<u8>) -> Self {
        self.challenge = Some(challenge);
        self
    }

    /// Sets the DICE chain.
    #[must_use]
    pub fn dice_chain(mut self, dice_chain: ChainForm) -> Self {
        self.dice_chain = Some(dice_chain);
        self
    }

    /// Sets the UDS certificates.
    #[must_use]
    pub fn uds_certs(mut self, uds_certs: HashMap<String, Vec<X509>>) -> Self {
        self.uds_certs = Some(uds_certs);
        self
    }

    /// Sets the CSR payload.
    #[must_use]
    pub fn csr_payload(mut self, csr_payload: CsrPayload) -> Self {
        self.csr_payload = Some(csr_payload);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::rkp::csr::testutil::{parse_pem_public_key_or_panic, test_device_info};
    use crate::dice::{ChainForm, DegenerateChain};
    use crate::rkp::device_info::DeviceInfoVersion;
    use crate::rkp::protected_data::ProtectedData;
    use anyhow::{Context, Result};
    use coset::{iana, CoseKey, CoseKeyBuilder};
    use openssl::bn::BigNum;

    fn create_test_key() -> Result<CoseKey> {
        let x = BigNum::from_u32(1234).context("Failed to create x coord")?;
        let y = BigNum::from_u32(4321).context("Failed to create y coord")?;
        Ok(CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x.to_vec(), y.to_vec())
            .build())
    }

    #[test]
    fn build_and_debug_csr_v2() {
        let device_info = test_device_info(DeviceInfoVersion::V2);
        let challenge = b"challenge".to_vec();
        let root_public_key = parse_pem_public_key_or_panic(
            "-----BEGIN PUBLIC KEY-----\n\
                MCowBQYDK2VwAyEArqr7jIIQ8TB1+l/Sh69eiSJL6t6txO1oLhpkdVSUuBk=\n\
                -----END PUBLIC KEY-----\n",
        );

        let degenerate_chain = DegenerateChain::new("test_issuer", "test_subject", root_public_key)
            .expect("Failed to create certificate chain");
        let protected_data =
            ProtectedData::new(vec![0; 32], ChainForm::Degenerate(degenerate_chain), None);

        let csr = CsrV2Builder::default()
            .device_info(device_info.clone())
            .challenge(challenge.clone())
            .protected_data(protected_data.clone())
            .build()
            .expect("Failed to build CSR V2");

        let expected = format!(
            "CSR V2 {{ DeviceInfo: {device_info:?}, Challenge: {:?}, ProtectedData: {protected_data:?} }}",
            hex::encode(&challenge)
        );

        assert_eq!(format!("{csr:?}"), expected);
    }

    #[test]
    fn build_and_debug_csr_v3() {
        let device_info = test_device_info(DeviceInfoVersion::V3);

        let challenge = b"challenge".to_vec();

        let serialized_payload = b"serialized_payload".to_vec();
        let certificate_type = "test_certificate_type".to_string();
        let mut keys_to_sign_vec = Vec::new();
        let key = create_test_key().expect("Failed to create test key");
        keys_to_sign_vec.push(key);

        let keys_to_sign = KeysToSign(keys_to_sign_vec);

        let csr_payload = CsrPayload {
            serialized: serialized_payload,
            certificate_type,
            device_info: device_info.clone(),
            keys_to_sign,
        };
        let root_public_key = parse_pem_public_key_or_panic(
            "-----BEGIN PUBLIC KEY-----\n\
                MCowBQYDK2VwAyEArqr7jIIQ8TB1+l/Sh69eiSJL6t6txO1oLhpkdVSUuBk=\n\
                -----END PUBLIC KEY-----\n",
        );
        let degenerate_chain = DegenerateChain::new("test_issuer", "test_subject", root_public_key)
            .expect("Failed to create certificate chain");
        let dice_chain = ChainForm::Degenerate(degenerate_chain);
        let uds_certs = HashMap::new();

        let csr = CsrV3Builder::default()
            .challenge(challenge.clone())
            .dice_chain(dice_chain.clone())
            .uds_certs(uds_certs.clone())
            .csr_payload(csr_payload.clone())
            .build()
            .expect("Failed to build CSR V3");

        let expected = format!(
            "CSR V3 {{ DeviceInfo: {device_info:?}, DiceChain: {dice_chain:?}, UdsCerts: {uds_certs:?} }}",
        );

        assert_eq!(format!("{csr:?}"), expected);
    }
}
