//! Split a firmware xpub into the Connect 10 public-key fields.
//!
//! Firmware returns the SLIP-132 form for the requested script type.
//! Connect keeps that string as `displayablePublicKey` / `xpubSegwit` and
//! rewrites `xpub` back to the legacy `xpub`/`tpub` version bytes.

use bitcoin::base58::{decode_check, encode_check};

use crate::types::bitcoin::ScriptType;

const XPUB: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];
const YPUB: [u8; 4] = [0x04, 0x9D, 0x7C, 0xB2];
const ZPUB: [u8; 4] = [0x04, 0xB2, 0x47, 0x46];
const TPUB: [u8; 4] = [0x04, 0x35, 0x87, 0xCF];
const UPUB: [u8; 4] = [0x04, 0x4A, 0x52, 0x62];
const VPUB: [u8; 4] = [0x04, 0x5F, 0x1C, 0xF6];

/// `(xpub, xpub_segwit, displayable_public_key)`.
pub(crate) fn public_key_forms(
    device_xpub: &str,
    script_type: ScriptType,
    descriptor: Option<String>,
) -> (String, Option<String>, String) {
    let (xpub, xpub_segwit) = match legacy_and_segwit(device_xpub) {
        Some(pair) => pair,
        None => (device_xpub.to_string(), None),
    };

    let displayable = if script_type == ScriptType::SpendTaproot {
        descriptor
            .clone()
            .unwrap_or_else(|| xpub_segwit.clone().unwrap_or_else(|| xpub.clone()))
    } else {
        xpub_segwit.clone().unwrap_or_else(|| xpub.clone())
    };

    let xpub_segwit = if script_type == ScriptType::SpendTaproot {
        descriptor.or(xpub_segwit)
    } else {
        xpub_segwit
    };

    (xpub, xpub_segwit, displayable)
}

fn legacy_and_segwit(device_xpub: &str) -> Option<(String, Option<String>)> {
    let mut payload = decode_check(device_xpub).ok()?;
    if payload.len() < 4 {
        return None;
    }
    let version: [u8; 4] = payload[..4].try_into().ok()?;
    let legacy = legacy_version(version)?;
    if legacy == version {
        return Some((device_xpub.to_string(), None));
    }
    payload[..4].copy_from_slice(&legacy);
    Some((encode_check(&payload), Some(device_xpub.to_string())))
}

fn legacy_version(version: [u8; 4]) -> Option<[u8; 4]> {
    match version {
        XPUB | YPUB | ZPUB => Some(XPUB),
        TPUB | UPUB | VPUB => Some(TPUB),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_payload(version: [u8; 4]) -> Vec<u8> {
        let mut payload = vec![0u8; 78];
        payload[..4].copy_from_slice(&version);
        payload[45] = 0x02;
        payload[46] = 0x79;
        payload[47] = 0xbe;
        payload
    }

    #[test]
    fn zpub_becomes_legacy_xpub_and_stays_displayable() {
        let device = encode_check(&sample_payload(ZPUB));
        let (xpub, segwit, displayable) = public_key_forms(&device, ScriptType::SpendWitness, None);
        assert_eq!(displayable, device);
        assert_eq!(segwit.as_deref(), Some(device.as_str()));
        assert!(xpub.starts_with("xpub"));
        assert_ne!(xpub, device);
    }

    #[test]
    fn legacy_xpub_has_no_segwit_form() {
        let device = encode_check(&sample_payload(XPUB));
        let (xpub, segwit, displayable) = public_key_forms(&device, ScriptType::SpendAddress, None);
        assert_eq!(xpub, device);
        assert_eq!(displayable, device);
        assert!(segwit.is_none());
    }

    #[test]
    fn taproot_prefers_firmware_descriptor() {
        let device = encode_check(&sample_payload(XPUB));
        let descriptor = "tr([aabbccdd/86'/0'/0']xpub/0/*)".to_string();
        let (_, segwit, displayable) =
            public_key_forms(&device, ScriptType::SpendTaproot, Some(descriptor.clone()));
        assert_eq!(displayable, descriptor);
        assert_eq!(segwit.as_deref(), Some(descriptor.as_str()));
    }

    #[test]
    fn non_base58_xpub_is_passed_through() {
        let (xpub, segwit, displayable) =
            public_key_forms("xpub-mock", ScriptType::SpendWitness, None);
        assert_eq!(xpub, "xpub-mock");
        assert_eq!(displayable, "xpub-mock");
        assert!(segwit.is_none());
    }

    #[test]
    fn invalid_checksum_is_passed_through() {
        let mut device = encode_check(&sample_payload(ZPUB));
        let last = device.pop().unwrap();
        device.push(if last == '1' { '2' } else { '1' });
        assert!(decode_check(&device).is_err());
        let (xpub, segwit, displayable) = public_key_forms(&device, ScriptType::SpendWitness, None);
        assert_eq!(xpub, device);
        assert_eq!(displayable, device);
        assert!(segwit.is_none());
    }
}
