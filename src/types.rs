use std::io::BufReader;
use std::process::Child;
use serde::{Deserialize, Serialize};

pub struct TrezorClient {
    pub(crate) process: Child,
    pub(crate) reader: BufReader<std::process::ChildStdout>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddressInfo {
    pub path: Vec<u32>,
    pub serializedPath: String,
    pub address: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrezorResponse<T> {
    #[serde(default)]
    pub id: u32,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<DeviceInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub path: String,
    pub state: DeviceState,
    pub instance: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceState {
    #[serde(default)]
    pub deriveCardano: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sessionId: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub staticSessionId: Option<String>,
}

// For the getFeatures response
#[derive(Debug, Serialize, Deserialize)]
pub struct TrezorDeviceFeatures {
    pub vendor: String,
    pub major_version: u8,
    pub minor_version: u8,
    pub patch_version: u8,
    #[serde(default)]
    pub bootloader_mode: Option<bool>,
    pub device_id: String,
    pub pin_protection: bool,
    pub passphrase_protection: bool,
    pub language: String,
    pub label: String,
    pub initialized: bool,
    pub revision: String,
    #[serde(default)]
    pub bootloader_hash: Option<String>,
    #[serde(default)]
    pub imported: Option<bool>,
    pub unlocked: bool,
    #[serde(rename = "*passphrase*cached")]
    #[serde(default)]
    pub passphrase_cached: Option<bool>,
    #[serde(default)]
    pub firmware_present: Option<bool>,
    pub backup_availability: String,
    pub flags: u32,
    pub model: String,
    #[serde(default)]
    pub fw_major: Option<u8>,
    #[serde(default)]
    pub fw_minor: Option<u8>,
    #[serde(default)]
    pub fw_patch: Option<u8>,
    pub fw_vendor: String,
    pub unfinished_backup: bool,
    pub no_backup: bool,
    pub recovery_status: String,
    pub capabilities: Vec<String>,
    pub backup_type: String,
    pub sd_card_present: bool,
    pub sd_protection: bool,
    pub wipe_code_protection: bool,
    pub session_id: String,
    pub passphrase_always_on_device: bool,
    pub safety_checks: String,
    pub auto_lock_delay_ms: u32,
    pub display_rotation: String,
    pub experimental_features: bool,
    pub busy: bool,
    pub homescreen_format: String,
    pub hide_passphrase_from_host: bool,
    pub internal_model: String,
    pub unit_color: u8,
    pub unit_btconly: bool,
    pub homescreen_width: u16,
    pub homescreen_height: u16,
    pub bootloader_locked: bool,
    pub language_version_matches: bool,
    pub unit_packaging: u8,
    pub haptic_feedback: bool,
    #[serde(default)]
    pub recovery_type: Option<String>,
    pub optiga_sec: u8,
}

// Updated for getPublicKey response
#[derive(Debug, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct PublicKeyInfo {
    pub path: Vec<u32>,
    pub serializedPath: String,
    pub childNum: u32,
    pub xpub: String,
    pub chainCode: String,
    pub publicKey: String,
    pub fingerprint: u32,
    pub depth: u8,
    pub descriptor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xpubSegwit: Option<String>,
}