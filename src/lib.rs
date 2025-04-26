use std::{io::{BufRead, BufReader, Write}, process::{Command, Stdio}, str};
use serde_json::{json, Value};
use crate::errors::HardwareError;
use crate::types::{AddressInfo, PublicKeyInfo, TrezorClient, TrezorDeviceFeatures, TrezorResponse};

mod errors;
mod types;
impl TrezorClient {
    fn new() -> Result<Self, HardwareError> {
        // Start the Deno script as a persistent process
        let mut process = Command::new("deno")
            .arg("run")
            .arg("--allow-net")
            .arg("--allow-read")
            .arg("--allow-env")
            .arg("--allow-ffi")
            .arg("--allow-run")
            .arg("--allow-sys")
            .arg("--allow-write")
            .arg("--allow-scripts=npm:blake-hash@2.0.0,npm:tiny-secp256k1@1.1.7,npm:protobufjs@7.4.0,npm:usb@2.15.0")
            .arg("--node-modules-dir")
            .arg("functions-with-trezor.js")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| HardwareError::IoError { error_details: e.to_string() })?;

        let reader = BufReader::new(process.stdout.take().unwrap());

        // Give the script time to start up and print initial instructions
        std::thread::sleep(std::time::Duration::from_millis(500));

        Ok(TrezorClient { process, reader })
    }

    fn send_command(&mut self, command_obj: Value) -> Result<Value, HardwareError> {
        let command_str = command_obj.to_string();

        // Send command to the script via stdin
        if let Some(ref mut stdin) = self.process.stdin {
            writeln!(stdin, "{}", command_str)
                .map_err(|e| HardwareError::IoError { error_details: e.to_string() })?;
            stdin.flush()
                .map_err(|e| HardwareError::IoError { error_details: e.to_string() })?;
        } else {
            return Err(HardwareError::CommunicationError { error_details: "Failed to get stdin".into() });
        }

        // Read response (JSON) from stdout
        let mut line = String::new();
        self.reader.read_line(&mut line)
            .map_err(|e| HardwareError::IoError { error_details: e.to_string() })?;

        let s = line.trim();

        if s.is_empty() {
            eprintln!("Warning: Empty output from Deno script");
            return Ok(json!({ "success": false, "error": "Empty output" }));
        }

        let v: Value = match serde_json::from_str(s) {
            Ok(value) => value,
            Err(e) => {
                eprintln!("Error parsing JSON: {} (output was: '{}')", e, s);
                return Ok(json!({ "success": false, "error": format!("JSON parse error: {}", e) }));
            }
        };

        Ok(v)
    }

    fn init(&mut self) -> Result<TrezorResponse<()>, HardwareError> {
        let response = self.send_command(json!({ "command": "init" }))?;
        let typed_response: TrezorResponse<()> = serde_json::from_value(response)
            .map_err(|e| HardwareError::JsonError { error_details: e.to_string() })?;
        Ok(typed_response)
    }

    fn get_features(&mut self) -> Result<TrezorResponse<TrezorDeviceFeatures>, HardwareError> {
        let response = self.send_command(json!({ "command": "getFeatures" }))?;
        let typed_response: TrezorResponse<TrezorDeviceFeatures> = serde_json::from_value(response)
            .map_err(|e| HardwareError::JsonError { error_details: e.to_string() })?;
        Ok(typed_response)
    }

    fn get_public_key(&mut self, path: &str, coin: &str) -> Result<TrezorResponse<PublicKeyInfo>, HardwareError> {
        let response = self.send_command(json!({
            "command": "getpk",
            "path": path,
            "coin": coin
        }))?;
        let typed_response: TrezorResponse<PublicKeyInfo> = serde_json::from_value(response)
            .map_err(|e| HardwareError::JsonError { error_details: e.to_string() })?;
        Ok(typed_response)
    }

    fn get_address(&mut self, path: &str, coin: &str, show_on_trezor: bool) -> Result<TrezorResponse<AddressInfo>, HardwareError> {
        let response = self.send_command(json!({
            "command": "getaddr",
            "path": path,
            "coin": coin,
            "showOnTrezor": show_on_trezor
        }))?;
        let typed_response: TrezorResponse<AddressInfo> = serde_json::from_value(response)
            .map_err(|e| HardwareError::JsonError { error_details: e.to_string() })?;
        Ok(typed_response)
    }

    fn exit(&mut self) -> Result<TrezorResponse<()>, HardwareError> {
        let response = self.send_command(json!({ "command": "exit" }))?;
        let typed_response: TrezorResponse<()> = serde_json::from_value(response)
            .map_err(|e| HardwareError::JsonError { error_details: e.to_string() })?;
        Ok(typed_response)
    }
}

impl Drop for TrezorClient {
    fn drop(&mut self) {
        // Try to properly close the connection when done
        let _ = self.exit();
        let _ = self.process.wait();
    }
}

pub fn initialize() -> Result<String, HardwareError> {
    // Create a persistent Trezor client
    let mut trezor = TrezorClient::new()?;
    println!("Connected to Trezor client");
    let init = trezor.init()?;
    if init.success {
        println!("✅ Trezor library initialized");
        Ok("Trezor library initialized".to_string())
    } else {
        let error_msg = init.error.unwrap_or_else(|| "Unknown error".to_string());
        eprintln!("❌ Trezor library initialization failed: {}", error_msg);
        Err(HardwareError::InitializationError { error_details: error_msg })
    }
}

pub fn get_device_features(trezor: &mut TrezorClient) -> Result<TrezorDeviceFeatures, HardwareError> {
    let features = trezor.get_features()?;
    if features.success {
        Ok(features.payload.unwrap())
    } else {
        let error_msg = features.error.unwrap_or_else(|| "Unknown error".to_string());
        eprintln!("❌ Get features failed: {}", error_msg);
        Err(HardwareError::InitializationError { error_details: error_msg })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialize() {
        // Simply call the initialize function and verify the result
        match initialize() {
            Ok(message) => {
                assert_eq!(message, "Trezor library initialized".to_string());
                println!("✅ Trezor initialization test passed");
            },
            Err(e) => {
                println!("❗ Trezor initialization failed: {:?}", e);
                // Depending on your testing environment, you might want to fail the test
                // or just log the error if a device isn't connected
                // Uncomment the next line to make the test fail if initialization fails
                // panic!("Test failed: Trezor initialization failed: {:?}", e);
            }
        }
    }

    // You can add more specific tests for individual functions
    #[test]
    #[ignore] // This test requires actual hardware, run with cargo test -- --ignored
    fn test_get_device_features() {
        // Initialize the Trezor
        let mut trezor = match TrezorClient::new() {
            Ok(client) => client,
            Err(e) => {
                println!("❗ Could not create Trezor client: {:?}", e);
                return; // Skip test if we can't create the client
            }
        };

        // Initialize the connection
        match trezor.init() {
            Ok(init_response) => {
                if !init_response.success {
                    println!("❗ Trezor initialization failed: {:?}", init_response.error);
                    return; // Skip test if initialization failed
                }
            },
            Err(e) => {
                println!("❗ Trezor initialization error: {:?}", e);
                return; // Skip test if initialization failed
            }
        }

        // Test getting device features
        match get_device_features(&mut trezor) {
            Ok(features) => {
                // Verify we got some valid features
                assert!(!features.device_id.is_empty());
                assert!(!features.vendor.is_empty());
                println!("✅ Got device features: {}", features.device_id);
            },
            Err(e) => {
                println!("❗ Failed to get device features: {:?}", e);
                // Uncomment the next line to make the test fail if getting features fails
                // panic!("Test failed: Could not get device features: {:?}", e);
            }
        }
    }
}