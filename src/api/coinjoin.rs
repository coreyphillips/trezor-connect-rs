//! CoinJoin authorization API.

use crate::error::Result;
use crate::types::bitcoin::ScriptType;

/// Parameters for authorize_coinjoin
#[derive(Debug, Clone)]
pub struct AuthorizeCoinJoinParams {
    /// Derivation path
    pub path: String,
    /// Coordinator URL
    pub coordinator: String,
    /// Maximum rounds
    pub max_rounds: u32,
    /// Maximum coordinator fee rate
    pub max_coordinator_fee_rate: u32,
    /// Maximum fee per kvB
    pub max_fee_per_kvbyte: u32,
    /// Coin name
    pub coin: String,
    /// Script type
    pub script_type: ScriptType,
}

/// Authorize a CoinJoin session
pub async fn authorize_coinjoin(_params: AuthorizeCoinJoinParams) -> Result<()> {
    // TODO: Implement
    Ok(())
}

/// Cancel CoinJoin authorization
pub async fn cancel_coinjoin_authorization() -> Result<()> {
    // TODO: Implement
    Ok(())
}

/// Parameters for get_ownership_id
#[derive(Debug, Clone)]
pub struct GetOwnershipIdParams {
    /// Derivation path
    pub path: String,
    /// Coin name
    pub coin: String,
    /// Script type
    pub script_type: ScriptType,
}

/// Ownership ID response
#[derive(Debug, Clone)]
pub struct OwnershipId {
    /// Ownership ID (hex)
    pub ownership_id: String,
}

/// Get ownership ID
pub async fn get_ownership_id(_params: GetOwnershipIdParams) -> Result<OwnershipId> {
    // TODO: Implement
    Ok(OwnershipId {
        ownership_id: String::new(),
    })
}

/// Parameters for get_ownership_proof
#[derive(Debug, Clone)]
pub struct GetOwnershipProofParams {
    /// Derivation path
    pub path: String,
    /// Coin name
    pub coin: String,
    /// Script type
    pub script_type: ScriptType,
    /// Commitment data
    pub commitment_data: Option<String>,
}

/// Ownership proof response
#[derive(Debug, Clone)]
pub struct OwnershipProof {
    /// Ownership proof (hex)
    pub ownership_proof: String,
}

/// Get ownership proof
pub async fn get_ownership_proof(_params: GetOwnershipProofParams) -> Result<OwnershipProof> {
    // TODO: Implement
    Ok(OwnershipProof {
        ownership_proof: String::new(),
    })
}
