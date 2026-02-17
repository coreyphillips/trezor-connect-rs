//! Compose transaction API.

use crate::error::Result;

/// Compose transaction parameters
#[derive(Debug, Clone)]
pub struct ComposeTransactionParams {
    /// Outputs to include
    pub outputs: Vec<ComposeOutput>,
    /// Coin name
    pub coin: String,
    /// Fee per byte
    pub fee_per_byte: u64,
}

/// Output specification for compose
#[derive(Debug, Clone)]
pub struct ComposeOutput {
    /// Output type
    pub output_type: OutputType,
    /// Address (for payment)
    pub address: Option<String>,
    /// Amount in satoshis
    pub amount: Option<u64>,
}

/// Output type
#[derive(Debug, Clone)]
pub enum OutputType {
    /// Payment to address
    Payment,
    /// Change output
    Change,
    /// Send max (all remaining)
    SendMax,
}

/// Composed transaction result
#[derive(Debug, Clone)]
pub struct ComposedTransaction {
    /// Total fee
    pub fee: u64,
    /// Transaction bytes
    pub bytes: usize,
    /// Inputs to use
    pub inputs: Vec<super::sign_tx::TxInput>,
    /// Outputs
    pub outputs: Vec<super::sign_tx::TxOutput>,
}

/// Compose a transaction
pub async fn compose_transaction(_params: ComposeTransactionParams) -> Result<ComposedTransaction> {
    // TODO: Implement - requires blockchain data
    Ok(ComposedTransaction {
        fee: 0,
        bytes: 0,
        inputs: vec![],
        outputs: vec![],
    })
}
