//! Transport layer for Trezor communication.
//!
//! This module provides abstractions for communicating with Trezor devices
//! over different transports (USB, Bluetooth, Callback).

pub mod traits;
pub mod session;
pub mod callback;

#[cfg(feature = "usb")]
pub mod usb;

#[cfg(feature = "bluetooth")]
pub mod bluetooth;

pub use traits::*;
pub use session::*;
pub use callback::*;
