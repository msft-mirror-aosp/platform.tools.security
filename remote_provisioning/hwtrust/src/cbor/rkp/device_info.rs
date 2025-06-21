use crate::cbor::field_value::FieldValue;
use crate::rkp::{
    DeviceInfo, DeviceInfoBootloaderState, DeviceInfoSecurityLevel, DeviceInfoVbState,
    DeviceInfoVersion,
};
use crate::session::DeviceInfoRange;
use anyhow::{bail, ensure, Context, Result};
use chrono::NaiveDate;
use ciborium::value::Value;

impl DeviceInfo {
    /// Create a new DeviceInfo struct from Values parsed by ciborium
    pub fn from_cbor_values(
        values: Vec<(Value, Value)>,
        device_info_range: &DeviceInfoRange,
        is_factory: bool,
    ) -> Result<Self> {
        let mut brand = FieldValue::new("brand");
        let mut manufacturer = FieldValue::new("manufacturer");
        let mut product = FieldValue::new("product");
        let mut model = FieldValue::new("model");
        let mut device = FieldValue::new("device");
        let mut vb_state = FieldValue::new("vb_state");
        let mut bootloader_state = FieldValue::new("bootloader_state");
        let mut vbmeta_digest = FieldValue::new("vbmeta_digest");
        let mut os_version = FieldValue::new("os_version");
        let mut system_patch_level = FieldValue::new("system_patch_level");
        let mut boot_patch_level = FieldValue::new("boot_patch_level");
        let mut vendor_patch_level = FieldValue::new("vendor_patch_level");
        let mut security_level = FieldValue::new("security_level");
        let mut version = FieldValue::new("version");
        let mut fused = FieldValue::new("fused");
        let mut att_id_state = FieldValue::new("att_id_state");

        for (key, value) in values {
            let field_value = match key.as_text() {
                Some("brand") => &mut brand,
                Some("manufacturer") => &mut manufacturer,
                Some("product") => &mut product,
                Some("model") => &mut model,
                Some("device") => &mut device,
                Some("vb_state") => &mut vb_state,
                Some("bootloader_state") => &mut bootloader_state,
                Some("vbmeta_digest") => &mut vbmeta_digest,
                Some("os_version") => &mut os_version,
                Some("system_patch_level") => &mut system_patch_level,
                Some("boot_patch_level") => &mut boot_patch_level,
                Some("vendor_patch_level") => &mut vendor_patch_level,
                Some("security_level") => &mut security_level,
                Some("fused") => &mut fused,
                Some("att_id_state") => &mut att_id_state,
                Some("version") => &mut version,
                _ => bail!("Unexpected DeviceInfo kv-pair: ({key:?},{value:?})"),
            };
            field_value.set_once(value)?;
        }

        let parsed_version = match version.into_optional_u32()? {
            None => DeviceInfoVersion::V3,
            Some(version) => {
                let v = DeviceInfoVersion::try_from(version).context("Unexpected version")?;
                ensure!(
                    v != DeviceInfoVersion::V3,
                    "Version should not be included in V3 DeviceInfos"
                );
                v
            }
        };

        ensure!(
            device_info_range.contains(parsed_version),
            concat!(
                "Expected DeviceInfo version range: {device_info_range:?} does not match parsed",
                " version: {parsed_version:?}"
            ),
        );

        let fused = match parsed_version {
            DeviceInfoVersion::V1 => {
                ensure!(
                    fused.into_optional_u32()?.is_none(),
                    "fused state doesn't exist for DeviceInfoVersion::V1"
                );
                match att_id_state.into_optional_string()?.as_deref() {
                    Some("locked") => 1,
                    Some("open") => 0,
                    Some(_) => bail!("att_id_state must be 'locked' or 'open'"),
                    None => bail!("att_id_state must be set"),
                }
            }
            _ => {
                ensure!(
                    att_id_state.into_optional_string()?.is_none(),
                    "att_id_state doesn't exist for DeviceInfoVersion > V1"
                );
                fused.into_u32()?
            }
        };

        let info = DeviceInfo {
            brand: brand.into_optional_string()?,
            manufacturer: manufacturer.into_optional_string()?,
            product: product.into_optional_string()?,
            model: model.into_optional_string()?,
            device: device.into_optional_string()?,
            vb_state: vb_state
                .into_optional_string()?
                .as_deref()
                .map(|x| x.try_into())
                .transpose()?,
            bootloader_state: bootloader_state
                .into_optional_string()?
                .as_deref()
                .map(|x| x.try_into())
                .transpose()?,
            vbmeta_digest: vbmeta_digest.into_optional_bytes()?,
            os_version: os_version.into_optional_string()?,
            system_patch_level: system_patch_level.into_optional_u32()?,
            boot_patch_level: boot_patch_level.into_optional_u32()?,
            vendor_patch_level: vendor_patch_level.into_optional_u32()?,
            security_level: security_level.into_string()?.as_str().try_into()?,
            fused,
            version: parsed_version,
        };
        info.validate(is_factory)?;
        Ok(info)
    }

    fn validate(&self, is_factory: bool) -> Result<()> {
        if DeviceInfoSecurityLevel::Avf == self.security_level {
            ensure!(
                self.bootloader_state == Some(DeviceInfoBootloaderState::Avf)
                    && self.vb_state == Some(DeviceInfoVbState::Avf)
                    && self.brand == Some("aosp-avf".to_string())
                    && self.device == Some("avf".to_string())
                    && self.model == Some("avf".to_string())
                    && self.manufacturer == Some("aosp-avf".to_string())
                    && self.product == Some("avf".to_string()),
                "AVF security level requires AVF fields. Got: {:?}",
                self
            );
            return Ok(());
        } else {
            ensure!(
                self.bootloader_state != Some(DeviceInfoBootloaderState::Avf)
                    && self.vb_state != Some(DeviceInfoVbState::Avf)
                    && self.brand != Some("aosp-avf".to_string())
                    && self.device != Some("avf".to_string())
                    && self.model != Some("avf".to_string())
                    && self.manufacturer != Some("aosp-avf".to_string())
                    && self.product != Some("avf".to_string()),
                "Non-AVF security level requires non-AVF fields. Got: {:?}",
                self
            );
        }

        if !is_factory {
            self.check_entries()?;
        }

        Ok(())
    }

    fn check_patch_level(key: &str, level: &Option<u32>) -> Result<()> {
        if level.is_none() {
            return Ok(());
        }

        let mut maybe_modified_level = level.unwrap().to_string();
        if maybe_modified_level.len() == 6 {
            maybe_modified_level += "01";
        }

        let string = maybe_modified_level.as_str();
        match string.len() {
            8 => match NaiveDate::parse_from_str(string, "%Y%m%d") {
                Ok(_) => Ok(()),
                Err(e) => bail!("Error parsing {key}:{}: {}", level.unwrap(), e.to_string()),
            },
            _ => bail!(
                "value for {key} must be in format YYYYMMDD or YYYYMM, found: '{}'",
                level.unwrap()
            ),
        }
    }

    fn check_entries(&self) -> Result<()> {
        if self.version == DeviceInfoVersion::V2 || self.version == DeviceInfoVersion::V3 {
            ensure!(
                self.manufacturer.as_ref().is_some_and(|x| !x.is_empty()),
                "manufacturer must not be empty"
            );
            ensure!(self.vbmeta_digest.is_some(), "vbmeta_digest must not be none");
            ensure!(self.vb_state.is_some(), "vb_state must not be none");
            ensure!(self.bootloader_state.is_some(), "bootloader_state must must not be none");
            ensure!(
                self.fused == 0 || self.fused == 1,
                "fused must be a valid production value {}",
                self.fused
            );
            ensure!(
                self.security_level != DeviceInfoSecurityLevel::Tee
                    || self.os_version.as_ref().is_some_and(|x| !x.is_empty()),
                "OS version is not optional with TEE"
            );
            ensure!(self.brand.as_ref().is_some_and(|x| !x.is_empty()), "brand must not be empty");
            ensure!(
                self.device.as_ref().is_some_and(|x| !x.is_empty()),
                "device must not be empty"
            );
            ensure!(self.model.as_ref().is_some_and(|x| !x.is_empty()), "model must not be empty");
            ensure!(
                self.product.as_ref().is_some_and(|x| !x.is_empty()),
                "product must not be empty"
            );
            ensure!(self.system_patch_level.is_some(), "system_patch_level must not be none");
            ensure!(self.boot_patch_level.is_some(), "boot_patch_level must not be none");
            ensure!(self.vendor_patch_level.is_some(), "vendor_patch_level must not be none");
        }

        Self::check_patch_level("system_patch_level", &self.system_patch_level)?;
        Self::check_patch_level("boot_patch_level", &self.boot_patch_level)?;
        Self::check_patch_level("vendor_patch_level", &self.vendor_patch_level)?;
        ensure!(
            self.security_level != DeviceInfoSecurityLevel::Factory,
            "security_level must be a valid production value"
        );
        ensure!(
            self.vbmeta_digest.as_ref().map_or(true, |d| !d.iter().all(|b| *b == 0u8)),
            "vbmeta_digest must not be all zeros. Got {:?}",
            self.vbmeta_digest
        );
        ensure!(
            self.vb_state != Some(DeviceInfoVbState::Factory),
            "vb_state must be a valid production value"
        );
        ensure!(
            self.bootloader_state != Some(DeviceInfoBootloaderState::Factory),
            "bootloader_state must be a valid production value"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rkp::DeviceInfoVersion;

    #[test]
    fn device_info_from_cbor_values_optional_os_version() {
        let values: Vec<(Value, Value)> = get_valid_values_filtered(|x| x != "os_version");
        let info = DeviceInfo::from_cbor_values(
            values,
            &DeviceInfoRange::single(DeviceInfoVersion::V2),
            true,
        )
        .unwrap();
        assert!(info.os_version.is_none());
    }

    #[test]
    fn device_info_from_cbor_values_optional_os_version_is_not_optional_with_tee() {
        let values: Vec<(Value, Value)> = get_valid_tee_values_filtered(|x| x != "os_version");
        let err = DeviceInfo::from_cbor_values(
            values,
            &DeviceInfoRange::single(DeviceInfoVersion::V2),
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("OS version is not optional with TEE"));
    }

    #[test]
    fn device_info_from_cbor_values_missing_required_field() {
        let values: Vec<(Value, Value)> = get_valid_values_filtered(|x| x != "brand");
        let err = DeviceInfo::from_cbor_values(
            values,
            &DeviceInfoRange::single(DeviceInfoVersion::V2),
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("brand"));
    }

    #[test]
    fn device_info_from_cbor_values_missing_v1_optional_field() {
        let values: Vec<(Value, Value)> = get_valid_v1_values_filtered(|x| x != "brand");
        let info = DeviceInfo::from_cbor_values(
            values,
            &DeviceInfoRange::single(DeviceInfoVersion::V1),
            false,
        )
        .unwrap();
        assert!(info.brand.is_none());
    }

    #[test]
    fn device_info_from_cbor_values_v1_fused_open() {
        let mut values: Vec<(Value, Value)> = get_valid_v1_values_filtered(|x| x != "att_id_state");
        values.push(("att_id_state".into(), "open".into()));
        let info = DeviceInfo::from_cbor_values(
            values,
            &DeviceInfoRange::single(DeviceInfoVersion::V1),
            false,
        )
        .unwrap();
        assert_eq!(info.fused, 0);
    }

    #[test]
    fn device_info_from_cbor_values_valid_v1() {
        let actual = DeviceInfo::from_cbor_values(
            get_valid_v1_values(),
            &DeviceInfoRange::single(DeviceInfoVersion::V1),
            false,
        )
        .unwrap();
        let mut expected = expected_device_info();
        expected.version = DeviceInfoVersion::V1;
        assert_eq!(actual, expected);
    }

    #[test]
    fn device_info_from_cbor_values_valid_v2() {
        let actual = DeviceInfo::from_cbor_values(
            get_valid_values(),
            &DeviceInfoRange::single(DeviceInfoVersion::V2),
            false,
        )
        .unwrap();
        let expected = expected_device_info();
        assert_eq!(actual, expected);
    }

    #[test]
    fn device_info_from_cbor_values_valid_v3() {
        let values: Vec<(Value, Value)> = get_valid_values_filtered(|x| x != "version");
        let actual = DeviceInfo::from_cbor_values(
            values,
            &DeviceInfoRange::single(DeviceInfoVersion::V3),
            false,
        )
        .unwrap();
        let mut expected = expected_device_info();
        expected.version = DeviceInfoVersion::V3;
        assert_eq!(actual, expected);
    }

    #[test]
    fn device_info_from_cbor_values_v1_out_of_range() {
        let err = DeviceInfo::from_cbor_values(
            get_valid_v1_values(),
            &DeviceInfoRange::new(DeviceInfoVersion::V2, DeviceInfoVersion::V3),
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("does not match parsed version: V1"));
    }

    #[test]
    fn device_info_from_cbor_values_v2_in_range() {
        let actual = DeviceInfo::from_cbor_values(
            get_valid_values(),
            &DeviceInfoRange::new(DeviceInfoVersion::V1, DeviceInfoVersion::V3),
            false,
        )
        .unwrap();
        let expected = expected_device_info();
        assert_eq!(actual, expected);
    }

    #[test]
    fn device_info_from_cbor_values_mismatched_version() {
        let values: Vec<(Value, Value)> = get_valid_values();
        let err = DeviceInfo::from_cbor_values(
            values,
            &DeviceInfoRange::single(DeviceInfoVersion::V3),
            false,
        )
        .unwrap_err();
        println!("{err:?}");
        assert!(err.to_string().contains("version"));
    }

    #[test]
    fn device_info_from_cbor_values_missing_version() {
        let values: Vec<(Value, Value)> = get_valid_values_filtered(|x| x != "version");
        let err = DeviceInfo::from_cbor_values(
            values,
            &DeviceInfoRange::single(DeviceInfoVersion::V2),
            false,
        )
        .unwrap_err();
        println!("{err:?}");
        assert!(err.to_string().contains("version"));
    }

    #[test]
    fn device_info_from_cbor_duplicate_values() {
        let mut values: Vec<(Value, Value)> = get_valid_values();
        values.push(("brand".into(), "generic".into()));

        let err = DeviceInfo::from_cbor_values(
            values,
            &DeviceInfoRange::single(DeviceInfoVersion::V2),
            false,
        )
        .unwrap_err();
        println!("{err:?}");
        assert!(err.to_string().contains("may be set only once"));
    }

    #[test]
    fn device_info_from_cbor_no_vbmeta_digest() {
        let values: Vec<(Value, Value)> = get_valid_values_filtered(|v| v != "vbmeta_digest");
        let err = DeviceInfo::from_cbor_values(
            values,
            &DeviceInfoRange::single(DeviceInfoVersion::V2),
            false,
        )
        .unwrap_err();
        println!("{err:?}");
        assert!(err.to_string().contains("vbmeta_digest must not be none"), "{err:?}");
    }

    #[test]
    fn device_info_from_cbor_all_zero_vbmeta_digest() {
        let mut values: Vec<(Value, Value)> = get_valid_values_filtered(|v| v != "vbmeta_digest");
        values.push(("vbmeta_digest".into(), vec![0u8; 16].into()));

        let err = DeviceInfo::from_cbor_values(
            values,
            &DeviceInfoRange::single(DeviceInfoVersion::V2),
            false,
        )
        .unwrap_err();
        println!("{err:?}");
        assert!(err.to_string().contains("vbmeta_digest must not be all zeros"), "{err:?}");
    }

    #[test]
    fn device_info_from_cbor_values_non_avf_security_level_has_avf_vb_state() {
        let mut values = get_valid_values_filtered(|x| x != "vb_state");
        values.push(("vb_state".into(), "avf".into()));

        let err = DeviceInfo::from_cbor_values(
            values,
            &DeviceInfoRange::single(DeviceInfoVersion::V2),
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("Non-AVF security level"), "{err:?}");
    }

    #[test]
    fn device_info_from_cbor_values_non_avf_security_level_has_avf_bootloader_state() {
        let mut values = get_valid_values_filtered(|x| x != "bootloader_state");
        values.push(("bootloader_state".into(), "avf".into()));

        let err = DeviceInfo::from_cbor_values(
            values,
            &DeviceInfoRange::single(DeviceInfoVersion::V2),
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("Non-AVF security level"), "{err:?}");
    }

    #[test]
    fn device_info_from_cbor_values_avf_security_level_has_non_avf_vb_state() {
        let values: Vec<(Value, Value)> = get_valid_avf_values()
            .into_iter()
            .filter(|(k, _v)| k.as_text().unwrap() != "vb_state")
            .chain(vec![("vb_state".into(), "green".into())])
            .collect();
        let err = DeviceInfo::from_cbor_values(
            values,
            &DeviceInfoRange::single(DeviceInfoVersion::V3),
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("AVF security level requires AVF fields"), "{err:?}");
    }

    #[test]
    fn device_info_from_cbor_values_avf_security_level_has_avf_fields() {
        let values = get_valid_avf_values();
        let actual = DeviceInfo::from_cbor_values(
            values,
            &DeviceInfoRange::single(DeviceInfoVersion::V3),
            false,
        )
        .unwrap();
        let expected = DeviceInfo {
            brand: Some("aosp-avf".to_string()),
            manufacturer: Some("aosp-avf".to_string()),
            product: Some("avf".to_string()),
            model: Some("avf".to_string()),
            device: Some("avf".to_string()),
            vb_state: Some(DeviceInfoVbState::Avf),
            bootloader_state: Some(DeviceInfoBootloaderState::Avf),
            vbmeta_digest: Some(b"abcdefg".to_vec()),
            os_version: Some("dessert".to_string()),
            system_patch_level: Some(303010),
            boot_patch_level: Some(30300102),
            vendor_patch_level: Some(30300304),
            security_level: DeviceInfoSecurityLevel::Avf,
            fused: 1,
            version: DeviceInfoVersion::V3,
        };
        assert_eq!(expected, actual);
    }

    fn expected_device_info() -> DeviceInfo {
        DeviceInfo {
            brand: Some("generic".to_string()),
            manufacturer: Some("acme".to_string()),
            product: Some("phone".to_string()),
            model: Some("the best one".to_string()),
            device: Some("really the best".to_string()),
            vb_state: Some(DeviceInfoVbState::Green),
            bootloader_state: Some(DeviceInfoBootloaderState::Locked),
            vbmeta_digest: Some(b"abcdefg".to_vec()),
            os_version: Some("dessert".to_string()),
            system_patch_level: Some(303010),
            boot_patch_level: Some(30300102),
            vendor_patch_level: Some(30300304),
            security_level: DeviceInfoSecurityLevel::StrongBox,
            fused: 1,
            version: DeviceInfoVersion::V2,
        }
    }

    fn get_valid_values() -> Vec<(Value, Value)> {
        vec![
            ("brand".into(), "generic".into()),
            ("manufacturer".into(), "acme".into()),
            ("product".into(), "phone".into()),
            ("model".into(), "the best one".into()),
            ("device".into(), "really the best".into()),
            ("vb_state".into(), "green".into()),
            ("bootloader_state".into(), "locked".into()),
            ("vbmeta_digest".into(), b"abcdefg".as_ref().into()),
            ("os_version".into(), "dessert".into()),
            ("system_patch_level".into(), 303010.into()),
            ("boot_patch_level".into(), 30300102.into()),
            ("vendor_patch_level".into(), 30300304.into()),
            ("security_level".into(), "strongbox".into()),
            ("fused".into(), 1.into()),
            ("version".into(), 2.into()),
        ]
    }

    fn get_valid_tee_values() -> Vec<(Value, Value)> {
        let mut values = get_valid_values_filtered(|x| x != "security_level");
        values.push(("security_level".into(), "tee".into()));
        values
    }

    fn get_valid_v1_values() -> Vec<(Value, Value)> {
        let mut values = get_valid_values_filtered(|x| x != "version" && x != "fused");
        values.push(("att_id_state".into(), "locked".into()));
        values.push(("version".into(), 1.into()));
        values
    }

    fn get_valid_avf_values() -> Vec<(Value, Value)> {
        vec![
            ("brand".into(), "aosp-avf".into()),
            ("manufacturer".into(), "aosp-avf".into()),
            ("product".into(), "avf".into()),
            ("model".into(), "avf".into()),
            ("device".into(), "avf".into()),
            ("vb_state".into(), "avf".into()),
            ("bootloader_state".into(), "avf".into()),
            ("vbmeta_digest".into(), b"abcdefg".as_ref().into()),
            ("os_version".into(), "dessert".into()),
            ("system_patch_level".into(), 303010.into()),
            ("boot_patch_level".into(), 30300102.into()),
            ("vendor_patch_level".into(), 30300304.into()),
            ("security_level".into(), "avf".into()),
            ("fused".into(), 1.into()),
        ]
    }

    fn get_valid_values_filtered<F: Fn(&str) -> bool>(filter: F) -> Vec<(Value, Value)> {
        get_valid_values().into_iter().filter(|x| filter(x.0.as_text().unwrap())).collect()
    }

    fn get_valid_tee_values_filtered<F: Fn(&str) -> bool>(filter: F) -> Vec<(Value, Value)> {
        get_valid_tee_values().into_iter().filter(|x| filter(x.0.as_text().unwrap())).collect()
    }

    fn get_valid_v1_values_filtered<F: Fn(&str) -> bool>(filter: F) -> Vec<(Value, Value)> {
        get_valid_v1_values().into_iter().filter(|x| filter(x.0.as_text().unwrap())).collect()
    }
}
