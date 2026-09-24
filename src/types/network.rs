//! Bitcoin network information.

use serde::{Deserialize, Serialize};

/// Bitcoin network type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Network {
    #[default]
    Bitcoin,
    Testnet,
    Regtest,
}

impl Network {
    /// Firmware coin name (`GetAddress.coin_name` and friends).
    ///
    /// This is the protobuf field, not the Connect 10 public shortcut.
    /// Callers pass [`Self::shortcut`] (`btc`, `test`, `regtest`).
    pub fn coin_name(&self) -> &'static str {
        match self {
            Network::Bitcoin => "Bitcoin",
            Network::Testnet => "Testnet",
            Network::Regtest => "Regtest",
        }
    }

    /// Connect 10 coin shortcut. Matching is case-insensitive.
    pub fn shortcut(&self) -> &'static str {
        match self {
            Network::Bitcoin => "btc",
            Network::Testnet => "test",
            Network::Regtest => "regtest",
        }
    }

    /// Resolve a Connect 10 coin shortcut.
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
    /// regtest. Any other coin type returns `None`.
    pub fn from_derivation_path(path: &[u32]) -> Option<Self> {
        let slip44 = path.get(1)? & 0x7fff_ffff;
        match slip44 {
            0 => Some(Network::Bitcoin),
            1 => Some(Network::Testnet),
            _ => None,
        }
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
}
