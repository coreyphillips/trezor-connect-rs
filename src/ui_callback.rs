//! UI callback trait for PIN and passphrase input.
//!
//! Provides a mechanism for the host application to handle PIN and passphrase
//! requests from the Trezor device, instead of returning hard errors.

/// Callback trait for handling PIN and passphrase requests from the device.
///
/// Implement this trait to provide PIN/passphrase input from your application's UI.
/// Methods are synchronous because UniFFI does not support async callback interfaces.
///
/// # Example
/// ```ignore
/// struct MyUiCallback;
///
/// impl TrezorUiCallback for MyUiCallback {
///     fn on_pin_request(&self) -> Option<String> {
///         // Show PIN matrix UI, return entered PIN or None to cancel
///         Some("123456".to_string())
///     }
///
///     fn on_passphrase_request(&self, on_device: bool) -> Option<String> {
///         if on_device {
///             // User will enter on device; return Some("") to acknowledge
///             Some(String::new())
///         } else {
///             // Show passphrase input UI
///             Some("my passphrase".to_string())
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
    /// If `on_device` is true, the user should enter the passphrase on the
    /// Trezor itself — return `Some("")` to acknowledge.
    ///
    /// If `on_device` is false, return `Some(passphrase)` with the user input,
    /// or `None` to cancel.
    fn on_passphrase_request(&self, on_device: bool) -> Option<String>;
}
