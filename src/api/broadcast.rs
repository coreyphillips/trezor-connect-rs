//! Push/broadcast transaction API.

use crate::error::Result;

/// Parameters for push_transaction
#[derive(Debug, Clone)]
pub struct PushTransactionParams {
    /// Signed transaction hex
    pub tx: String,
    /// Coin name
    pub coin: String,
}

/// Push transaction response
#[derive(Debug, Clone)]
pub struct PushedTransaction {
    /// Transaction ID
    pub txid: String,
}

/// Push a transaction to the network
pub async fn push_transaction(_params: PushTransactionParams) -> Result<PushedTransaction> {
    // TODO: Implement - requires blockchain connection
    Ok(PushedTransaction {
        txid: String::new(),
    })
}
