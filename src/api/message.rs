//! Sign and verify message API.

use crate::error::Result;

/// Parameters for sign_message
#[derive(Debug, Clone)]
pub struct SignMessageParams {
    /// Derivation path
    pub path: String,
    /// Message to sign
    pub message: String,
    /// Coin name
    pub coin: String,
}

/// Message signature response
#[derive(Debug, Clone)]
pub struct MessageSignature {
    /// Signing address
    pub address: String,
    /// Signature (base64)
    pub signature: String,
}

/// Parameters for verify_message
#[derive(Debug, Clone)]
pub struct VerifyMessageParams {
    /// Address to verify against
    pub address: String,
    /// Signature (base64)
    pub signature: String,
    /// Original message
    pub message: String,
    /// Coin name
    pub coin: String,
}

/// Sign a message
pub async fn sign_message(_params: SignMessageParams) -> Result<MessageSignature> {
    // TODO: Implement
    Ok(MessageSignature {
        address: String::new(),
        signature: String::new(),
    })
}

/// Verify a message signature
pub async fn verify_message(_params: VerifyMessageParams) -> Result<bool> {
    // TODO: Implement
    Ok(true)
}
