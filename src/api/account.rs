//! Get account info API.

use crate::error::{DeviceError, Result, TrezorError};
use crate::types::network::Network;

/// Parameters for get_account_info
#[derive(Debug, Clone)]
pub struct GetAccountInfoParams {
    /// Coin shortcut (`btc`, `test`, `regtest`). Names such as `Bitcoin` are rejected.
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

/// Get account information.
///
/// **Not implemented**: this crate has no blockchain backend. Account data
/// (balances, UTXOs) must be fetched by the caller from their own chain
/// source (e.g. Electrum or Blockbook).
#[deprecated(note = "No blockchain backend in this crate; fetch account data externally")]
pub async fn get_account_info(params: GetAccountInfoParams) -> Result<AccountInfo> {
    Network::from_shortcut(&params.coin).ok_or(DeviceError::UnknownCoin)?;
    if params.path.is_none() && params.descriptor.is_none() {
        return Err(DeviceError::InvalidParameter(
            "GetAccountInfo: path or descriptor is required".into(),
        )
        .into());
    }
    Err(TrezorError::NotImplemented(
        "api::get_account_info; this crate has no blockchain backend",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn get_account_info_rejects_coin_name() {
        let err = futures::executor::block_on(get_account_info(GetAccountInfoParams {
            coin: "Bitcoin".into(),
            path: Some("m/84'/0'/0'".into()),
            descriptor: None,
        }))
        .unwrap_err();
        assert!(matches!(err, TrezorError::Device(DeviceError::UnknownCoin)));
    }

    #[test]
    #[allow(deprecated)]
    fn get_account_info_requires_path_or_descriptor() {
        let err = futures::executor::block_on(get_account_info(GetAccountInfoParams {
            coin: "btc".into(),
            path: None,
            descriptor: None,
        }))
        .unwrap_err();
        assert!(matches!(
            err,
            TrezorError::Device(DeviceError::InvalidParameter(_))
        ));
    }
}
