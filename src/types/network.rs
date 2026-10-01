//! Bitcoin network information.

use serde::{Deserialize, Serialize};

/// Bitcoin network type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub enum Network {
    #[default]
    #[serde(rename = "btc")]
    Bitcoin,
    #[serde(rename = "test")]
    Testnet,
    #[serde(rename = "regtest")]
    Regtest,
}

impl<'de> Deserialize<'de> for Network {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let shortcut = String::deserialize(deserializer)?;
        Self::from_shortcut(&shortcut)
            .ok_or_else(|| serde::de::Error::custom("expected btc, test, or regtest"))
    }
}

impl Network {
    /// Firmware coin name (`GetAddress.coin_name` and friends).
    ///
    /// This is the protobuf field, not the Connect 10 public shortcut.
    /// Rust device parameters take this enum. Its serde representation uses
    /// [`Self::shortcut`] (`btc`, `test`, `regtest`).
    pub fn coin_name(&self) -> &'static str {
        match self {
            Network::Bitcoin => "Bitcoin",
            Network::Testnet => "Testnet",
            Network::Regtest => "Regtest",
        }
    }

    /// Connect 10 coin shortcut.
    pub fn shortcut(&self) -> &'static str {
        match self {
            Network::Bitcoin => "btc",
            Network::Testnet => "test",
            Network::Regtest => "regtest",
        }
    }

    /// Resolve a Connect 10 coin shortcut, case-insensitively.
    ///
    /// Names and labels (`Bitcoin`, `Testnet`) are not accepted.
    pub fn from_shortcut(raw: &str) -> Option<Self> {
        match raw.to_ascii_lowercase().as_str() {
            "btc" => Some(Network::Bitcoin),
            "test" => Some(Network::Testnet),
            "regtest" => Some(Network::Regtest),
            _ => None,
        }
    }

    /// Bitcoin network implied by the SLIP-44 coin type at path index 1.
    ///
    /// Only Bitcoin coin types are recognized. SLIP-44 `1` is both testnet
    /// and regtest; the path selects testnet. Pass `regtest` explicitly for
    /// regtest. Any other coin type returns `None`. Short paths and BIP-45
    /// paths have no coin type and retain the Rust API's Bitcoin default.
    pub fn from_derivation_path(path: &[u32]) -> Option<Self> {
        match Self::path_coin_type(path) {
            None | Some(0) => Some(Network::Bitcoin),
            Some(1) => Some(Network::Testnet),
            _ => None,
        }
    }

    pub(crate) fn path_coin_type(path: &[u32]) -> Option<u32> {
        if path.first().map(|purpose| purpose & 0x7fff_ffff) == Some(45) {
            return None;
        }
        path.get(1).map(|coin_type| coin_type & 0x7fff_ffff)
    }

    /// Get the BIP44 coin type
    pub fn coin_type(&self) -> u32 {
        match self {
            Network::Bitcoin => 0,
            Network::Testnet | Network::Regtest => 1,
        }
    }

    /// Get the bech32 HRP (Human-Readable Part)
    pub fn bech32_hrp(&self) -> &'static str {
        match self {
            Network::Bitcoin => "bc",
            Network::Testnet => "tb",
            Network::Regtest => "bcrt",
        }
    }

    /// Get the address version byte (P2PKH)
    pub fn p2pkh_prefix(&self) -> u8 {
        match self {
            Network::Bitcoin => 0x00,
            Network::Testnet | Network::Regtest => 0x6f,
        }
    }

    /// Get the script version byte (P2SH)
    pub fn p2sh_prefix(&self) -> u8 {
        match self {
            Network::Bitcoin => 0x05,
            Network::Testnet | Network::Regtest => 0xc4,
        }
    }

    /// Get the WIF prefix
    pub fn wif_prefix(&self) -> u8 {
        match self {
            Network::Bitcoin => 0x80,
            Network::Testnet | Network::Regtest => 0xef,
        }
    }

    /// Get the xpub version bytes
    pub fn xpub_version(&self) -> u32 {
        match self {
            Network::Bitcoin => 0x0488B21E,
            Network::Testnet | Network::Regtest => 0x043587CF,
        }
    }

    /// Get the xprv version bytes
    pub fn xprv_version(&self) -> u32 {
        match self {
            Network::Bitcoin => 0x0488ADE4,
            Network::Testnet | Network::Regtest => 0x04358394,
        }
    }
}

/// Coin information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinInfo {
    /// Coin name
    pub name: String,
    /// Coin shortcut (e.g., "BTC")
    pub shortcut: String,
    /// Network type
    pub network: Network,
    /// Decimals
    pub decimals: u8,
    /// Supports SegWit
    pub segwit: bool,
    /// Supports Taproot
    pub taproot: bool,
    /// Minimum fee per byte
    pub min_fee: u64,
    /// Maximum fee per byte
    pub max_fee: u64,
    /// Default fee per byte
    pub default_fee: u64,
    /// Dust limit in satoshis
    pub dust_limit: u64,
}

impl Default for CoinInfo {
    fn default() -> Self {
        Self {
            name: "Bitcoin".to_string(),
            shortcut: "BTC".to_string(),
            network: Network::Bitcoin,
            decimals: 8,
            segwit: true,
            taproot: true,
            min_fee: 1,
            max_fee: 2000,
            default_fee: 10,
            dust_limit: 546,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Network;

    #[test]
    fn shortcut_match_is_case_insensitive() {
        assert_eq!(Network::from_shortcut("BTC"), Some(Network::Bitcoin));
        assert_eq!(Network::from_shortcut("regtest"), Some(Network::Regtest));
        assert_eq!(Network::from_shortcut("Bitcoin"), None);
    }

    #[test]
    fn path_slip44_selects_bitcoin_or_testnet() {
        let mainnet = crate::types::path::parse_path("m/84'/0'/0'").unwrap();
        let testnet = crate::types::path::parse_path("m/84'/1'/0'").unwrap();
        let other = crate::types::path::parse_path("m/44'/60'/0'").unwrap();
        assert_eq!(
            Network::from_derivation_path(&mainnet),
            Some(Network::Bitcoin)
        );
        assert_eq!(
            Network::from_derivation_path(&testnet),
            Some(Network::Testnet)
        );
        assert_eq!(Network::from_derivation_path(&other), None);
    }

    #[test]
    fn paths_without_coin_type_default_to_bitcoin() {
        for path in ["m", "m/0'", "m/45'/0/0/0", "m/45'/1/0/0", "m/45'/2/0/0"] {
            let path = crate::types::path::parse_path(path).unwrap();
            assert_eq!(Network::from_derivation_path(&path), Some(Network::Bitcoin));
            assert_eq!(Network::path_coin_type(&path), None);
        }
    }

    #[test]
    fn serde_uses_case_insensitive_shortcuts() {
        for (coin, shortcut) in [
            (Network::Bitcoin, "btc"),
            (Network::Testnet, "test"),
            (Network::Regtest, "regtest"),
        ] {
            assert_eq!(serde_json::to_value(coin).unwrap(), shortcut);
            for value in [shortcut.to_string(), shortcut.to_uppercase()] {
                assert_eq!(
                    serde_json::from_value::<Network>(value.into()).unwrap(),
                    coin
                );
            }
        }
        assert_eq!(
            serde_json::from_str::<Network>("\"ReGtEsT\"").unwrap(),
            Network::Regtest
        );
        for name in ["Bitcoin", "Testnet", "ltc", ""] {
            assert!(serde_json::from_value::<Network>(name.into()).is_err());
        }
    }
}
