# Trezor Hardware Wallet Integration

This Rust library allows for interacting with Trezor hardware wallets through a Deno bridge script.

## Features

- Initialize connection to Trezor devices
- Retrieve device features and information
- Get public keys for specific derivation paths
- Get addresses for specific derivation paths
- Properly handle device connection and disconnection

## Requirements

- [Rust](https://www.rust-lang.org/tools/install)
- [Deno](https://deno.land/#installation)
- Node.js modules:
    - blake-hash@2.0.0
    - tiny-secp256k1@1.1.7
    - protobufjs@7.4.0
    - usb@2.15.0

## Installation

Add this crate to your Cargo.toml:

```toml
[dependencies]
trezor-connect-rs = "0.1.2"
```

Make sure the `functions-with-trezor.js` Deno script is available in your project directory.

## Usage

### Basic Example

```rust
use trezor_connect_rs::{initialize, TrezorClient};

fn main() {
    // Initialize the Trezor library
    match initialize() {
        Ok(message) => println!("Success: {}", message),
        Err(e) => eprintln!("Error: {:?}", e)
    }
    
    // Create a client to interact with the device
    let mut trezor = match TrezorClient::new() {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Could not create Trezor client: {:?}", e);
            return;
        }
    };
    
    // Initialize the connection
    if let Err(e) = trezor.init() {
        eprintln!("Initialization error: {:?}", e);
        return;
    }
    
    // Get device features
    match trezor.get_features() {
        Ok(features) => {
            if features.success {
                let device_info = features.payload.unwrap();
                println!("Connected to: {} ({})", device_info.model, device_info.device_id);
            } else {
                eprintln!("Failed to get features: {:?}", features.error);
            }
        },
        Err(e) => eprintln!("Error getting features: {:?}", e)
    }
    
    // Get a Bitcoin address (replace with your desired derivation path)
    let address_response = trezor.get_address("m/44'/0'/0'/0/0", "bitcoin", true);
    if let Ok(addr_resp) = address_response {
        if addr_resp.success {
            println!("Address: {}", addr_resp.payload.unwrap().address);
        }
    }
    
    // Client will automatically close the connection when it goes out of scope
}
```

### Working with Derivation Paths

The library supports BIP-32 derivation paths for various cryptocurrencies:

```rust
// Get Bitcoin address
let btc_address = trezor.get_address("m/44'/0'/0'/0/0", "bitcoin", false);

// Get Ethereum address
let eth_address = trezor.get_address("m/44'/60'/0'/0/0", "ethereum", false);
```

### Displaying on Trezor

To display the address on the Trezor device for verification:

```rust
// The last parameter (true) will show the address on the Trezor display
let safe_address = trezor.get_address("m/44'/0'/0'/0/0", "bitcoin", true);
```

## Error Handling

All functions return a `Result` type that will contain either the successful response or a `HardwareError` with details about what went wrong.

The library uses the `thiserror` crate to define the following error types:

```rust
pub enum HardwareError {
    // Failed to initialize the hardware wallet
    InitializationError { error_details: String },
    
    // I/O errors during communication
    IoError { error_details: String },
    
    // Error finding the executable directory
    ExecutableDirectoryError,
    
    // Communication errors with the device
    CommunicationError { error_details: String },
    
    // JSON serialization/deserialization errors
    JsonError { error_details: String },
}

## Testing

Basic tests are included:

```bash
# Run standard tests
cargo test

# Run tests that require physical Trezor hardware
cargo test -- --ignored
```

## Data Structures

### TrezorClient
The main client struct that manages communication with the device:
```rust
pub struct TrezorClient {
    pub(crate) process: Child,
    pub(crate) reader: BufReader<std::process::ChildStdout>,
}
```

### TrezorResponse<T>
All API calls return a generic response structure:
```rust
pub struct TrezorResponse<T> {
    pub id: u32,                            // Response ID
    pub success: bool,                      // Success/failure indicator
    pub payload: Option<T>,                 // Type-specific payload (when success is true)
    pub error: Option<String>,              // Error message (when success is false)
    pub message: Option<String>,            // Additional message
    pub device: Option<DeviceInfo>,         // Information about the connected device
}
```

### TrezorDeviceFeatures
Contains detailed information about the connected Trezor device, including:
- Device model and firmware version
- Security settings (PIN/passphrase protection)
- Device capabilities and state
- Hardware information

### AddressInfo
Contains information about a derived address:
```rust
pub struct AddressInfo {
    pub path: Vec<u32>,              // Numeric derivation path components
    pub serializedPath: String,      // String representation of path (e.g., "m/44'/0'/0'/0/0")
    pub address: String,             // The derived cryptocurrency address
}
```

### PublicKeyInfo
Contains extended public key information:
```rust
pub struct PublicKeyInfo {
    pub path: Vec<u32>,              // Numeric derivation path components
    pub serializedPath: String,      // String representation of path
    pub childNum: u32,               // Child number in the derivation path
    pub xpub: String,                // Extended public key (xpub format)
    pub chainCode: String,           // Chain code for derivation
    pub publicKey: String,           // Raw public key
    pub fingerprint: u32,            // Parent fingerprint
    pub depth: u8,                   // Derivation depth
    pub descriptor: String,          // Output descriptor
    pub xpubSegwit: Option<String>,  // Segwit extended public key (if applicable)
}
```

## Architecture

This library uses a Deno script (`functions-with-trezor.js`) as an intermediary between Rust and the Trezor device. Communication happens through stdin/stdout pipes with JSON-formatted messages.

## License

MIT