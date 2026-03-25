//! USB transport implementation.
//!
//! Uses the `rusb` crate for cross-platform USB communication.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::constants::{
    USB_CHUNK_SIZE, USB_ENDPOINT_IN, USB_ENDPOINT_OUT, USB_INTERFACE_ID,
    USB_PRODUCT_ID_BOOTLOADER, USB_PRODUCT_ID_FIRMWARE, USB_VENDOR_ID,
};
use crate::error::{Result, TransportError};
use crate::protocol::v1::ProtocolV1;
use crate::protocol::{chunk, Protocol};
use crate::transport::{DeviceDescriptor, SessionManager, Transport, TransportApi};

/// Timeout for USB operations in milliseconds
const USB_TIMEOUT_MS: u64 = 5000;

/// Holds device handle with detach state
struct OpenDevice {
    handle: rusb::DeviceHandle<rusb::GlobalContext>,
    has_kernel_driver: bool,
}

/// USB Transport for Trezor devices
pub struct UsbTransport {
    /// Session manager
    sessions: SessionManager,
    /// Open device handles (path -> handle)
    ///
    /// Uses std::sync::RwLock instead of tokio::sync::RwLock because handles
    /// are accessed from within spawn_blocking contexts. Using a tokio lock
    /// inside block_on/spawn_blocking can deadlock if the write lock is held
    /// by a tokio task waiting for a spawn_blocking slot.
    handles: Arc<std::sync::RwLock<HashMap<String, OpenDevice>>>,
    /// Protocol implementation
    protocol: ProtocolV1,
    /// Per-device call serialization locks (path -> mutex).
    /// Ensures only one call() is in-flight per device at a time.
    /// Uses std::sync::Mutex for the outer map (held briefly, never across .await).
    /// Uses tokio::sync::Mutex for per-device lock (held across .await to serialize calls).
    call_locks: Arc<std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
}

impl UsbTransport {
    /// Create a new USB transport
    pub fn new() -> Result<Self> {
        Ok(Self {
            sessions: SessionManager::new(),
            handles: Arc::new(std::sync::RwLock::new(HashMap::new())),
            protocol: ProtocolV1::usb(),
            call_locks: Arc::new(std::sync::Mutex::new(HashMap::new())),
        })
    }

    /// Get or create the per-device call serialization lock.
    fn get_call_lock(&self, path: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.call_locks.lock().expect("call_locks poisoned");
        locks
            .entry(path.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Find Trezor USB devices
    fn find_devices() -> Result<Vec<rusb::Device<rusb::GlobalContext>>> {
        let devices: Vec<_> = rusb::devices()
            .map_err(|e| TransportError::Usb(e.to_string()))?
            .iter()
            .filter(|d| {
                if let Ok(desc) = d.device_descriptor() {
                    desc.vendor_id() == USB_VENDOR_ID
                        && (desc.product_id() == USB_PRODUCT_ID_FIRMWARE
                            || desc.product_id() == USB_PRODUCT_ID_BOOTLOADER)
                } else {
                    false
                }
            })
            .collect();

        Ok(devices)
    }

    /// Get serial number from device
    fn get_serial_number(device: &rusb::Device<rusb::GlobalContext>) -> Option<String> {
        let desc = device.device_descriptor().ok()?;
        let handle = device.open().ok()?;
        let _timeout = Duration::from_millis(1000);
        handle.read_serial_number_string_ascii(&desc).ok()
    }
}

// NOTE: Default impl intentionally omitted. UsbTransport::new() returns Result
// and library code should not panic on initialization failure. Use
// UsbTransport::new() directly and handle the error.

#[async_trait]
impl TransportApi for UsbTransport {
    fn chunk_size(&self) -> usize {
        USB_CHUNK_SIZE
    }

    async fn enumerate(&self) -> Result<Vec<DeviceDescriptor>> {
        let devices = Self::find_devices()?;

        let descriptors: Vec<_> = devices
            .into_iter()
            .filter_map(|d| {
                let desc = d.device_descriptor().ok()?;
                let path = Self::get_serial_number(&d).unwrap_or_else(|| "unknown".to_string());
                Some(DeviceDescriptor {
                    path: path.clone(),
                    vendor_id: desc.vendor_id(),
                    product_id: desc.product_id(),
                    serial_number: Self::get_serial_number(&d),
                    session: self.sessions.get_session(&path),
                })
            })
            .collect();

        Ok(descriptors)
    }

    async fn open(&self, path: &str) -> Result<()> {
        let devices = Self::find_devices()?;

        let device = devices
            .into_iter()
            .find(|d| Self::get_serial_number(d).as_deref() == Some(path))
            .ok_or(TransportError::DeviceNotFound)?;

        log::debug!("[USB] Opening device: {}", path);

        let handle = device
            .open()
            .map_err(|e| TransportError::UnableToOpen(e.to_string()))?;

        // Check if kernel driver is attached and detach if necessary
        let has_kernel_driver = handle
            .kernel_driver_active(USB_INTERFACE_ID)
            .unwrap_or(false);

        if has_kernel_driver {
            log::debug!("[USB] Detaching kernel driver");
            handle
                .detach_kernel_driver(USB_INTERFACE_ID)
                .map_err(|e| TransportError::UnableToOpen(format!("detach_kernel_driver: {}", e)))?;
        }

        // Set active configuration
        log::debug!("[USB] Setting configuration to 1");
        match handle.set_active_configuration(1) {
            Ok(_) => {}
            Err(rusb::Error::Busy) => {
                log::debug!("[USB] Configuration already set (busy)");
            }
            Err(e) => {
                return Err(TransportError::UnableToOpen(format!("set_configuration: {}", e)).into());
            }
        }

        // Note: Skip device reset - it can invalidate the handle on some platforms
        // and trezor-suite only resets when re-acquiring sessions

        // Claim interface
        log::debug!("[USB] Claiming interface {}", USB_INTERFACE_ID);
        handle
            .claim_interface(USB_INTERFACE_ID)
            .map_err(|e| TransportError::UnableToOpen(format!("claim_interface: {}", e)))?;

        log::debug!("[USB] Interface claimed successfully");

        // Clear any stale data in the device buffer (with iteration and time limits)
        log::debug!("[USB] Clearing stale data...");
        let mut clear_buffer = vec![0u8; USB_CHUNK_SIZE];
        let clear_timeout = Duration::from_millis(100);
        let clear_deadline = Instant::now() + Duration::from_secs(1);
        for _ in 0..100 {
            if Instant::now() >= clear_deadline {
                log::debug!("[USB] Buffer clear deadline reached");
                break;
            }
            match handle.read_interrupt(USB_ENDPOINT_IN, &mut clear_buffer, clear_timeout) {
                Ok(n) if n > 0 => {
                    log::debug!("[USB] Cleared {} stale bytes", n);
                }
                _ => break,
            }
        }
        log::debug!("[USB] Buffer cleared");

        // Store handle
        let mut handles = self.handles.write()
            .map_err(|e| TransportError::UnableToOpen(format!("lock poisoned: {}", e)))?;
        handles.insert(
            path.to_string(),
            OpenDevice {
                handle,
                has_kernel_driver,
            },
        );

        Ok(())
    }

    async fn close(&self, path: &str) -> Result<()> {
        let mut handles = self.handles.write()
            .map_err(|e| TransportError::UnableToClose(format!("lock poisoned: {}", e)))?;
        if let Some(open_device) = handles.remove(path) {
            // Release interface
            let _ = open_device.handle.release_interface(USB_INTERFACE_ID);

            // Reattach kernel driver if we detached it
            if open_device.has_kernel_driver {
                let _ = open_device.handle.attach_kernel_driver(USB_INTERFACE_ID);
            }
        }
        Ok(())
    }

    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let path = path.to_string();
        let handles = self.handles.clone();

        // Use spawn_blocking for synchronous USB operations
        tokio::task::spawn_blocking(move || {
            let handles = handles.read()
                .map_err(|e| TransportError::DataTransfer(format!("lock poisoned: {}", e)))?;
            let open_device = handles
                .get(&path)
                .ok_or(TransportError::DeviceNotFound)?;

            let mut buffer = vec![0u8; USB_CHUNK_SIZE];
            let timeout = Duration::from_millis(USB_TIMEOUT_MS);

            // Retry loop - device may need time to respond
            let mut attempts = 0;
            let max_attempts = 10;
            loop {
                match open_device.handle.read_interrupt(USB_ENDPOINT_IN, &mut buffer, timeout) {
                    Ok(bytes_read) if bytes_read > 0 => {
                        buffer.truncate(bytes_read);
                        return Ok(buffer);
                    }
                    Ok(_) => {
                        // Got 0 bytes, retry
                        attempts += 1;
                        if attempts >= max_attempts {
                            return Err(TransportError::DataTransfer("No data received after retries".to_string()).into());
                        }
                        log::debug!("[USB] read_interrupt got 0 bytes, retrying ({}/{})", attempts, max_attempts);
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(rusb::Error::Timeout) => {
                        attempts += 1;
                        if attempts >= max_attempts {
                            return Err(TransportError::DataTransfer("Read timeout after retries".to_string()).into());
                        }
                        log::debug!("[USB] read_interrupt timeout, retrying ({}/{})", attempts, max_attempts);
                    }
                    Err(e) => {
                        return Err(TransportError::DataTransfer(e.to_string()).into());
                    }
                }
            }
        })
        .await
        .map_err(|e| TransportError::DataTransfer(e.to_string()))?
    }

    async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        let path = path.to_string();
        let data = data.to_vec();
        let handles = self.handles.clone();

        log::trace!(
            "[USB] write_interrupt to endpoint 0x{:02x}, {} bytes",
            USB_ENDPOINT_OUT,
            data.len()
        );

        // Use spawn_blocking for synchronous USB operations
        tokio::task::spawn_blocking(move || {
            let handles = handles.read()
                .map_err(|e| TransportError::DataTransfer(format!("lock poisoned: {}", e)))?;
            let open_device = handles
                .get(&path)
                .ok_or(TransportError::DeviceNotFound)?;

            let timeout = Duration::from_millis(USB_TIMEOUT_MS);

            let bytes_written = open_device
                .handle
                .write_interrupt(USB_ENDPOINT_OUT, &data, timeout)
                .map_err(|e| TransportError::DataTransfer(e.to_string()))?;

            log::trace!("[USB] write_interrupt completed: {} bytes", bytes_written);
            Ok(())
        })
        .await
        .map_err(|e| TransportError::DataTransfer(e.to_string()))?
    }
}

#[async_trait]
impl Transport for UsbTransport {
    async fn init(&mut self) -> Result<()> {
        // USB doesn't require initialization
        Ok(())
    }

    async fn enumerate(&self) -> Result<Vec<DeviceDescriptor>> {
        TransportApi::enumerate(self).await
    }

    async fn acquire(&self, path: &str, previous: Option<&str>) -> Result<String> {
        // Check if device is already open
        let needs_open = {
            let handles = self.handles.read()
                .map_err(|e| TransportError::DataTransfer(format!("lock poisoned: {}", e)))?;
            !handles.contains_key(path)
        };

        if needs_open {
            self.open(path).await?;
        }

        self.sessions
            .acquire(path, previous)
            .map_err(|e| TransportError::DataTransfer(e.to_string()).into())
    }

    async fn release(&self, session: &str) -> Result<()> {
        if let Some(path) = self.sessions.get_path(session) {
            self.close(&path).await?;
            // Clean up the call lock for this device
            if let Ok(mut locks) = self.call_locks.lock() {
                locks.remove(&path);
            }
        }
        self.sessions
            .release(session)
            .map_err(|e| TransportError::DataTransfer(e.to_string()).into())
    }

    async fn call(
        &self,
        session: &str,
        message_type: u16,
        data: &[u8],
    ) -> Result<(u16, Vec<u8>)> {
        let path = self
            .sessions
            .get_path(session)
            .ok_or(TransportError::DeviceNotFound)?;

        // Serialize all calls to the same device to prevent interleaved reads/writes
        let lock = self.get_call_lock(&path);
        let _guard = lock.lock().await;

        // Encode message
        let encoded = self.protocol.encode(message_type, data)?;

        log::debug!(
            "[USB] call: message_type={}, data_len={}, encoded_len={}",
            message_type,
            data.len(),
            encoded.len()
        );

        // Create chunks
        let (_, chunk_header) = self.protocol.get_headers(&encoded);
        let chunks = chunk::create_chunks(&encoded, &chunk_header, USB_CHUNK_SIZE);

        log::trace!("[USB] Sending {} chunk(s)", chunks.len());

        // Send all chunks
        for (i, c) in chunks.iter().enumerate() {
            log::trace!(
                "[USB] Writing chunk {}: {:02x?}",
                i,
                &c[..c.len().min(16)]
            );
            self.write(&path, c).await?;
        }

        log::trace!("[USB] All chunks sent, waiting for response...");

        // Read response - read chunks until we find Protocol v1 header
        let mut response_chunks = Vec::new();
        let mut first_chunk: Option<Vec<u8>> = None;

        // Read chunks looking for Protocol v1 header (without outer timeout to avoid race)
        for attempt in 0..20 {
            let chunk = self.read(&path).await?;

            if chunk.is_empty() {
                log::trace!("[USB] Read {} returned empty, retrying", attempt);
                continue;
            }

            log::trace!(
                "[USB] Read {} ({} bytes): {:02x?}",
                attempt,
                chunk.len(),
                &chunk[..chunk.len().min(16)]
            );

            // Check for Protocol v1 header: 0x3F (report) + 0x23 0x23 (magic)
            if chunk.len() >= 3 && chunk[0] == 0x3F && chunk[1] == 0x23 && chunk[2] == 0x23 {
                log::trace!("[USB] Found Protocol v1 header");
                first_chunk = Some(chunk);
                break;
            } else {
                // Skip non-Protocol v1 chunks (preamble/device info)
                log::debug!("[USB] Skipping non-Protocol v1 chunk (first bytes: {:02x} {:02x})",
                    chunk.get(0).unwrap_or(&0), chunk.get(1).unwrap_or(&0));
            }
        }

        let first_chunk = first_chunk
            .ok_or_else(|| TransportError::DataTransfer("No Protocol v1 header found".to_string()))?;

        let decoded = self.protocol.decode(&first_chunk)?;
        log::debug!(
            "[USB] Protocol v1 message: type={}, length={}",
            decoded.message_type, decoded.length
        );

        response_chunks.push(first_chunk);

        // Standard Protocol v1 handling
        let header_size = crate::constants::PROTOCOL_V1_HEADER_SIZE;
        let first_payload_size = USB_CHUNK_SIZE - header_size;
        let remaining = if decoded.length as usize > first_payload_size {
            decoded.length as usize - first_payload_size
        } else {
            0
        };

        if remaining > 0 {
            let continuation_payload = USB_CHUNK_SIZE - 1; // 1 byte for magic
            let num_chunks = (remaining + continuation_payload - 1) / continuation_payload;
            log::trace!("[USB] Need {} more chunks for {} remaining bytes", num_chunks, remaining);

            for _i in 0..num_chunks {
                let chunk = self.read(&path).await?;
                response_chunks.push(chunk);
            }
        }

        // Reassemble response
        let payload = chunk::reassemble_chunks(
            &response_chunks,
            header_size,
            1, // Continuation header is 1 byte
            decoded.length as usize,
        )?;

        log::debug!("[USB] Reassembled payload: {} bytes", payload.len());
        Ok((decoded.message_type, payload))
    }

    fn stop(&mut self) {
        // Clear call serialization locks
        if let Ok(mut locks) = self.call_locks.lock() {
            locks.clear();
        }
        // Release all interfaces and reattach kernel drivers before clearing handles
        if let Ok(mut handles) = self.handles.write() {
            for (path, open_device) in handles.drain() {
                log::debug!("[USB] Releasing interface for device: {}", path);
                let _ = open_device.handle.release_interface(USB_INTERFACE_ID);
                if open_device.has_kernel_driver {
                    let _ = open_device.handle.attach_kernel_driver(USB_INTERFACE_ID);
                }
            }
        }
    }
}
