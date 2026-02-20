//! Parameter types for Trezor API methods.
//!
//! These types match the trezor-suite API patterns for consistency.

use crate::types::bitcoin::ScriptType;
use crate::types::network::Network;
use serde::{Deserialize, Serialize};

/// Parameters for getting an address from the device.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GetAddressParams {
    /// BIP32 path (e.g., "m/84'/0'/0'/0/0")
    pub path: String,
    /// Coin network (default: Bitcoin)
    pub coin: Option<Network>,
    /// Whether to display the address on the device for confirmation
    pub show_on_trezor: bool,
    /// Script type (auto-detected from path if not specified)
    pub script_type: Option<ScriptType>,
    /// Multisig configuration (for multisig addresses)
    pub multisig: Option<MultisigConfig>,
}

/// Parameters for getting a public key from the device.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GetPublicKeyParams {
    /// BIP32 path (e.g., "m/84'/0'/0'")
    pub path: String,
    /// Coin network (default: Bitcoin)
    pub coin: Option<Network>,
    /// Whether to display on device for confirmation
    pub show_on_trezor: bool,
    /// Script type (auto-detected from path if not specified)
    pub script_type: Option<ScriptType>,
}

/// Parameters for signing a message.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SignMessageParams {
    /// BIP32 path for the signing key
    pub path: String,
    /// Message to sign
    pub message: String,
    /// Coin network (default: Bitcoin)
    pub coin: Option<Network>,
    /// If true, don't include script type in the signature
    pub no_script_type: bool,
}

/// Parameters for verifying a message signature.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerifyMessageParams {
    /// Bitcoin address that signed the message
    pub address: String,
    /// Signature (base64 encoded)
    pub signature: String,
    /// Original message
    pub message: String,
    /// Coin network (default: Bitcoin)
    pub coin: Option<Network>,
}

/// Multisig configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigConfig {
    /// Required number of signatures (m of n)
    pub m: u32,
    /// List of public keys (HDNode structures)
    pub pubkeys: Vec<MultisigPubkey>,
    /// Signatures (optional, for partially signed transactions)
    pub signatures: Option<Vec<String>>,
}

/// Public key for multisig.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigPubkey {
    /// Node containing the public key
    pub node: Option<HDNodeType>,
    /// Extended public key (xpub)
    pub xpub: Option<String>,
    /// Address derivation path relative to the node
    pub address_n: Vec<u32>,
}

/// HD node type for public key representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HDNodeType {
    /// Depth in the derivation path
    pub depth: u32,
    /// Fingerprint of the parent key
    pub fingerprint: u32,
    /// Child number
    pub child_num: u32,
    /// Chain code (32 bytes)
    pub chain_code: Vec<u8>,
    /// Public key (33 bytes, compressed)
    pub public_key: Vec<u8>,
}

/// Transaction input for signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignTxInput {
    /// Previous transaction hash (hex, 32 bytes)
    pub prev_hash: String,
    /// Previous output index
    pub prev_index: u32,
    /// BIP32 derivation path (e.g., "m/84'/0'/0'/0/0")
    pub path: String,
    /// Amount in satoshis
    pub amount: u64,
    /// Script type
    pub script_type: ScriptType,
    /// Sequence number (default: 0xFFFFFFFD for RBF)
    pub sequence: Option<u32>,
    /// Original transaction hash for RBF replacement (hex encoded)
    pub orig_hash: Option<String>,
    /// Original input index for RBF replacement
    pub orig_index: Option<u32>,
}

/// Transaction output for signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignTxOutput {
    /// Destination address (for external outputs)
    pub address: Option<String>,
    /// BIP32 path (for change outputs)
    pub path: Option<String>,
    /// Amount in satoshis
    pub amount: u64,
    /// Script type (for change outputs)
    pub script_type: Option<ScriptType>,
    /// OP_RETURN data (hex encoded, for data outputs)
    pub op_return_data: Option<String>,
    /// Original transaction hash for RBF replacement (hex encoded)
    pub orig_hash: Option<String>,
    /// Original output index for RBF replacement
    pub orig_index: Option<u32>,
}

/// Previous transaction data (for non-SegWit input verification).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignTxPrevTx {
    /// Transaction hash (hex encoded)
    pub hash: String,
    /// Transaction version
    pub version: u32,
    /// Lock time
    pub lock_time: u32,
    /// Transaction inputs
    pub inputs: Vec<SignTxPrevTxInput>,
    /// Transaction outputs
    pub outputs: Vec<SignTxPrevTxOutput>,
}

/// Input of a previous transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignTxPrevTxInput {
    /// Previous transaction hash (hex encoded)
    pub prev_hash: String,
    /// Previous output index
    pub prev_index: u32,
    /// Script signature (hex encoded)
    pub script_sig: String,
    /// Sequence number
    pub sequence: u32,
}

/// Output of a previous transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignTxPrevTxOutput {
    /// Amount in satoshis
    pub amount: u64,
    /// Script pubkey (hex encoded)
    pub script_pubkey: String,
}

/// Parameters for signing a transaction.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SignTxParams {
    /// Transaction inputs
    pub inputs: Vec<SignTxInput>,
    /// Transaction outputs
    pub outputs: Vec<SignTxOutput>,
    /// Coin network (default: Bitcoin)
    pub coin: Option<Network>,
    /// Lock time (default: 0)
    pub lock_time: Option<u32>,
    /// Version (default: 2)
    pub version: Option<u32>,
    /// Previous transactions (for non-SegWit input verification)
    pub prev_txs: Vec<SignTxPrevTx>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_address_params_default() {
        let params = GetAddressParams::default();
        assert!(params.path.is_empty());
        assert!(!params.show_on_trezor);
        assert!(params.coin.is_none());
        assert!(params.script_type.is_none());
    }

    #[test]
    fn test_sign_message_params() {
        let params = SignMessageParams {
            path: "m/84'/0'/0'/0/0".into(),
            message: "Hello".into(),
            ..Default::default()
        };
        assert_eq!(params.path, "m/84'/0'/0'/0/0");
        assert_eq!(params.message, "Hello");
    }
}
