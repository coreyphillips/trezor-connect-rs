//! Get account info API.

use crate::error::Result;

/// Parameters for get_account_info
#[derive(Debug, Clone)]
pub struct GetAccountInfoParams {
    /// Coin name
    pub coin: String,
    /// Derivation path (optional)
    pub path: Option<String>,
    /// Descriptor (optional)
    pub descriptor: Option<String>,
}

/// UTXO (unspent transaction output)
#[derive(Debug, Clone)]
pub struct Utxo {
    /// Transaction hash
    pub txid: String,
    /// Output index
    pub vout: u32,
    /// Amount in satoshis
    pub amount: u64,
    /// Block height (None if unconfirmed)
    pub height: Option<u32>,
    /// Derivation path
    pub path: String,
}

/// Account information response
#[derive(Debug, Clone)]
pub struct AccountInfo {
    /// Account descriptor
    pub descriptor: String,
    /// Legacy xpub
    pub legacy_xpub: Option<String>,
    /// Balance in satoshis
    pub balance: u64,
    /// Unconfirmed balance
    pub unconfirmed_balance: u64,
    /// UTXOs
    pub utxos: Vec<Utxo>,
    /// Derivation path
    pub path: Option<String>,
}

/// Get account information
pub async fn get_account_info(_params: GetAccountInfoParams) -> Result<AccountInfo> {
    // TODO: Implement - requires blockchain connection
    Ok(AccountInfo {
        descriptor: String::new(),
        legacy_xpub: None,
        balance: 0,
        unconfirmed_balance: 0,
        utxos: vec![],
        path: None,
    })
}
