//! UI callback trait for PIN and passphrase input.
//!
//! Provides a mechanism for the host application to handle PIN and passphrase
//! requests from the Trezor device, instead of returning hard errors.

/// Response variants for an `on_passphrase_request` callback.
///
/// Trezor's passphrase protocol distinguishes three cases that a single
/// `Option<String>` return value cannot represent unambiguously: a standard
/// wallet (no passphrase) is `Some("")` to the device, while user cancel is
/// `None`. Modeling them as a typed enum makes the contract self-documenting
/// at the callback boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PassphraseResponse {
    /// User cancelled — aborts the pending operation.
    Cancel,
    /// Standard wallet — no passphrase, equivalent to `Some("")` on the device.
    /// Also the correct response when `on_device` is true.
    Standard,
    /// Hidden wallet — derived from the supplied passphrase.
    Hidden { value: String },
}

/// Callback trait for handling PIN and passphrase requests from the device.
///
/// Implement this trait to provide PIN/passphrase input from your application's UI.
/// Methods are synchronous because UniFFI does not support async callback interfaces.
///
/// # Example
/// ```ignore
/// use trezor_connect_rs::{TrezorUiCallback, PassphraseResponse};
///
/// struct MyUiCallback;
///
/// impl TrezorUiCallback for MyUiCallback {
///     fn on_pin_request(&self) -> Option<String> {
///         // Show PIN matrix UI, return entered PIN or None to cancel
///         Some("123456".to_string())
///     }
///
///     fn on_passphrase_request(&self, on_device: bool) -> PassphraseResponse {
///         if on_device {
///             // User will enter on device; Standard acknowledges the prompt
///             PassphraseResponse::Standard
///         } else {
///             // Show passphrase input UI
///             PassphraseResponse::Hidden { value: "my passphrase".to_string() }
///         }
///     }
/// }
/// ```
pub trait TrezorUiCallback: Send + Sync {
    /// Called when the device requests a PIN.
    ///
    /// Return `Some(pin)` with the matrix-encoded PIN, or `None` to cancel.
    fn on_pin_request(&self) -> Option<String>;

    /// Called when the device requests a passphrase.
    ///
    /// Return one of:
    /// - [`PassphraseResponse::Cancel`] to abort the operation.
    /// - [`PassphraseResponse::Standard`] for a standard (no-passphrase) wallet,
    ///   or to acknowledge when `on_device` is true and the user will type on
    ///   the Trezor itself.
    /// - [`PassphraseResponse::Hidden`] with the user-entered passphrase to
    ///   open a hidden wallet.
    fn on_passphrase_request(&self, on_device: bool) -> PassphraseResponse;
}
