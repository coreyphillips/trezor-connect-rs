//! Connected device wrapper with high-level Bitcoin API.
//!
//! Provides a simple interface for interacting with connected Trezor devices,
//! abstracting away transport details and protocol differences.

use prost::Message;

use crate::device::Features;
use crate::device_info::DeviceInfo;
use crate::error::{DeviceError, Result};
use crate::params::*;
use crate::protos::{self, MessageType};
use crate::protos::bitcoin::{tx_ack, tx_request};
use crate::responses::*;
use crate::transport::Transport;
use crate::types::bitcoin::{ScriptType, OutputScriptType};
use crate::types::path::{parse_path, serialize_path};

/// A connected Trezor device with high-level API methods.
///
/// This struct wraps a transport connection and provides easy-to-use
/// methods for Bitcoin operations like getting addresses and signing messages.
pub struct ConnectedDevice {
    /// Device information
    info: DeviceInfo,
    /// Transport for communication (boxed for transport abstraction)
    transport: Box<dyn Transport>,
    /// Active session ID
    session: String,
    /// Cached device features
    features: Option<Features>,
}

impl ConnectedDevice {
    /// Create a new connected device wrapper.
    ///
    /// # Arguments
    /// * `info` - Device information
    /// * `transport` - Transport for communication (boxed for transport abstraction)
    /// * `session` - Active session ID
    pub fn new(
        info: DeviceInfo,
        transport: Box<dyn Transport>,
        session: String,
    ) -> Self {
        Self {
            info,
            transport,
            session,
            features: None,
        }
    }

    /// Get device information.
    pub fn info(&self) -> &DeviceInfo {
        &self.info
    }

    /// Get cached device features (available after initialize).
    pub fn features(&self) -> Option<&Features> {
        self.features.as_ref()
    }

    /// Get the session ID.
    pub fn session(&self) -> &str {
        &self.session
    }

    /// Initialize the device and get features.
    ///
    /// This should be called after connecting to get device information.
    ///
    /// For USB devices, this sends the Initialize message.
    /// For Bluetooth (THP) devices, this sends GetFeatures since the THP session
    /// was already created during connection via ThpCreateNewSession.
    pub async fn initialize(&mut self) -> Result<Features> {
        use crate::device_info::TransportType;

        let (resp_type, resp_data) = if self.info.transport_type == TransportType::Bluetooth {
            // For THP devices, use GetFeatures since session is already initialized
            // via ThpCreateNewSession during acquire()
            log::debug!("[Device] Using GetFeatures for Bluetooth/THP device");
            let get_features = protos::management::GetFeatures::default();
            self.transport.call(
                &self.session,
                MessageType::GetFeatures as u16,
                &get_features.encode_to_vec(),
            ).await?
        } else {
            // For USB devices, use Initialize
            log::debug!("[Device] Using Initialize for USB device");
            let init = protos::management::Initialize::default();
            self.transport.call(
                &self.session,
                MessageType::Initialize as u16,
                &init.encode_to_vec(),
            ).await?
        };

        let proto_features: protos::management::Features =
            self.handle_response(resp_type, resp_data).await?;

        let features = Features::from_proto(&proto_features);

        // Update device info with label from features
        if let Some(ref label) = features.label {
            self.info.label = Some(label.clone());
        }

        self.features = Some(features.clone());
        Ok(features)
    }

    /// Get a Bitcoin address.
    ///
    /// # Example
    /// ```ignore
    /// let address = device.get_address(GetAddressParams {
    ///     path: "m/84'/0'/0'/0/0".into(),
    ///     show_on_trezor: false,
    ///     ..Default::default()
    /// }).await?;
    /// println!("Address: {}", address.address);
    /// ```
    pub async fn get_address(&self, params: GetAddressParams) -> Result<AddressResponse> {
        let address_n = parse_path(&params.path)?;
        let script_type = params.script_type
            .unwrap_or_else(|| infer_script_type(&address_n));
        let coin_name = params.coin.unwrap_or_else(|| "Bitcoin".to_string());

        let request = protos::bitcoin::GetAddress {
            address_n: address_n.clone(),
            coin_name: Some(coin_name),
            show_display: Some(params.show_on_trezor),
            script_type: Some(script_type as i32),
            multisig: None,
            ignore_xpub_magic: None,
            chunkify: None,
        };

        let (resp_type, resp_data) = self.transport.call(
            &self.session,
            MessageType::GetAddress as u16,
            &request.encode_to_vec(),
        ).await?;

        let response: protos::bitcoin::Address =
            self.handle_response(resp_type, resp_data).await?;

        Ok(AddressResponse {
            path: address_n.clone(),
            serialized_path: serialize_path(&address_n),
            address: response.address,
        })
    }

    /// Get a public key (xpub).
    ///
    /// # Example
    /// ```ignore
    /// let pubkey = device.get_public_key(GetPublicKeyParams {
    ///     path: "m/84'/0'/0'".into(),
    ///     ..Default::default()
    /// }).await?;
    /// println!("XPub: {}", pubkey.xpub);
    /// ```
    pub async fn get_public_key(&self, params: GetPublicKeyParams) -> Result<PublicKeyResponse> {
        let address_n = parse_path(&params.path)?;
        let script_type = params.script_type
            .unwrap_or_else(|| infer_script_type(&address_n));
        let coin_name = params.coin.unwrap_or_else(|| "Bitcoin".to_string());

        let request = protos::bitcoin::GetPublicKey {
            address_n: address_n.clone(),
            ecdsa_curve_name: None,
            show_display: Some(params.show_on_trezor),
            coin_name: Some(coin_name),
            script_type: Some(script_type as i32),
            ignore_xpub_magic: None,
        };

        let (resp_type, resp_data) = self.transport.call(
            &self.session,
            MessageType::GetPublicKey as u16,
            &request.encode_to_vec(),
        ).await?;

        let response: protos::bitcoin::PublicKey =
            self.handle_response(resp_type, resp_data).await?;

        Ok(PublicKeyResponse {
            path: address_n.clone(),
            serialized_path: serialize_path(&address_n),
            xpub: response.xpub,
            chain_code: hex::encode(&response.node.chain_code),
            public_key: hex::encode(&response.node.public_key),
            depth: response.node.depth,
            fingerprint: response.node.fingerprint,
            child_num: response.node.child_num,
        })
    }

    /// Sign a message.
    ///
    /// # Example
    /// ```ignore
    /// let signature = device.sign_message(SignMessageParams {
    ///     path: "m/84'/0'/0'/0/0".into(),
    ///     message: "Hello Bitcoin!".into(),
    ///     ..Default::default()
    /// }).await?;
    /// println!("Signature: {}", signature.signature);
    /// ```
    pub async fn sign_message(&self, params: SignMessageParams) -> Result<SignedMessageResponse> {
        let address_n = parse_path(&params.path)?;
        let script_type = infer_script_type(&address_n);
        let coin_name = params.coin.unwrap_or_else(|| "Bitcoin".to_string());

        let request = protos::bitcoin::SignMessage {
            address_n,
            message: params.message.as_bytes().to_vec(),
            coin_name: Some(coin_name),
            script_type: Some(script_type as i32),
            no_script_type: if params.no_script_type { Some(true) } else { None },
            chunkify: None,
        };

        let (resp_type, resp_data) = self.transport.call(
            &self.session,
            MessageType::SignMessage as u16,
            &request.encode_to_vec(),
        ).await?;

        let response: protos::bitcoin::MessageSignature =
            self.handle_response(resp_type, resp_data).await?;

        use base64::Engine;
        let signature_base64 = base64::engine::general_purpose::STANDARD.encode(&response.signature);

        Ok(SignedMessageResponse {
            address: response.address,
            signature: signature_base64,
        })
    }

    /// Verify a message signature.
    ///
    /// # Example
    /// ```ignore
    /// let valid = device.verify_message(VerifyMessageParams {
    ///     address: "bc1q...".into(),
    ///     signature: "H...".into(),
    ///     message: "Hello Bitcoin!".into(),
    ///     ..Default::default()
    /// }).await?;
    /// println!("Valid: {}", valid);
    /// ```
    pub async fn verify_message(&self, params: VerifyMessageParams) -> Result<bool> {
        use base64::Engine;
        let signature_bytes = base64::engine::general_purpose::STANDARD
            .decode(&params.signature)
            .map_err(|e| DeviceError::InvalidInput(format!("Invalid base64 signature: {}", e)))?;

        let coin_name = params.coin.unwrap_or_else(|| "Bitcoin".to_string());

        let request = protos::bitcoin::VerifyMessage {
            address: params.address,
            signature: signature_bytes,
            message: params.message.as_bytes().to_vec(),
            coin_name: Some(coin_name),
            chunkify: None,
        };

        let (resp_type, resp_data) = self.transport.call(
            &self.session,
            MessageType::VerifyMessage as u16,
            &request.encode_to_vec(),
        ).await?;

        // On success, device returns Success message
        match MessageType::try_from(resp_type as i32) {
            Ok(MessageType::Success) => Ok(true),
            Ok(MessageType::Failure) => Ok(false),
            _ => {
                let _: protos::common::Success =
                    self.handle_response(resp_type, resp_data).await?;
                Ok(true)
            }
        }
    }

    /// Sign a Bitcoin transaction.
    ///
    /// This implements the TxRequest/TxAck flow used by Trezor for transaction signing.
    ///
    /// # Example
    /// ```ignore
    /// let signed = device.sign_transaction(SignTxParams {
    ///     inputs: vec![SignTxInput {
    ///         prev_hash: "abc123...".into(),
    ///         prev_index: 0,
    ///         path: "m/84'/0'/0'/0/0".into(),
    ///         amount: 100000,
    ///         script_type: ScriptType::SpendWitness,
    ///         sequence: None,
    ///     }],
    ///     outputs: vec![SignTxOutput {
    ///         address: Some("bc1q...".into()),
    ///         path: None,
    ///         amount: 90000,
    ///         script_type: None,
    ///         op_return_data: None,
    ///     }],
    ///     ..Default::default()
    /// }).await?;
    /// println!("Signed TX: {}", signed.serialized_tx);
    /// ```
    pub async fn sign_transaction(&self, params: SignTxParams) -> Result<SignedTxResponse> {
        let coin_name = params.coin.unwrap_or_else(|| "Bitcoin".to_string());
        let version = params.version.unwrap_or(2);
        let lock_time = params.lock_time.unwrap_or(0);

        // Parse all input paths upfront
        let parsed_inputs: Vec<(Vec<u32>, ScriptType)> = params
            .inputs
            .iter()
            .map(|input| {
                let path = parse_path(&input.path)?;
                Ok((path, input.script_type))
            })
            .collect::<Result<Vec<_>>>()?;

        // Parse output paths for change outputs
        let parsed_outputs: Vec<Option<(Vec<u32>, ScriptType)>> = params
            .outputs
            .iter()
            .map(|output| {
                if let Some(ref path_str) = output.path {
                    let path = parse_path(path_str)?;
                    let script_type = output.script_type.unwrap_or_else(|| infer_script_type(&path));
                    Ok(Some((path, script_type)))
                } else {
                    Ok(None)
                }
            })
            .collect::<Result<Vec<_>>>()?;

        // Send initial SignTx message
        let sign_tx = protos::bitcoin::SignTx {
            outputs_count: params.outputs.len() as u32,
            inputs_count: params.inputs.len() as u32,
            coin_name: Some(coin_name),
            version: Some(version),
            lock_time: Some(lock_time),
            expiry: None,
            overwintered: None,
            version_group_id: None,
            timestamp: None,
            branch_id: None,
            amount_unit: None,
            decred_staking_ticket: None,
            serialize: None,
            coinjoin_request: None,
            chunkify: None,
        };

        let (mut resp_type, mut resp_data) = self.transport.call(
            &self.session,
            MessageType::SignTx as u16,
            &sign_tx.encode_to_vec(),
        ).await?;

        let mut signatures: Vec<String> = vec![String::new(); params.inputs.len()];
        let mut serialized_tx = Vec::new();

        // TxRequest/TxAck loop
        loop {
            // Handle button requests
            if let Ok(MessageType::ButtonRequest) = MessageType::try_from(resp_type as i32) {
                let ack = protos::common::ButtonAck {};
                let result = self.transport.call(
                    &self.session,
                    MessageType::ButtonAck as u16,
                    &ack.encode_to_vec(),
                ).await?;
                resp_type = result.0;
                resp_data = result.1;
                continue;
            }

            // Handle failure
            if let Ok(MessageType::Failure) = MessageType::try_from(resp_type as i32) {
                let failure = protos::common::Failure::decode(resp_data.as_slice())
                    .map_err(|e| DeviceError::ProtobufDecode(e.to_string()))?;
                return Err(DeviceError::DeviceError {
                    code: failure.code.unwrap_or(0),
                    message: failure.message.unwrap_or_default(),
                }.into());
            }

            // Parse TxRequest
            let tx_request = protos::bitcoin::TxRequest::decode(resp_data.as_slice())
                .map_err(|e| DeviceError::ProtobufDecode(e.to_string()))?;

            // Collect serialized data if present
            if let Some(ref serialized) = tx_request.serialized {
                if let Some(ref sig) = serialized.signature {
                    if let Some(sig_idx) = serialized.signature_index {
                        let idx = sig_idx as usize;
                        if idx < signatures.len() {
                            signatures[idx] = hex::encode(sig);
                        } else {
                            return Err(DeviceError::InvalidInput(
                                format!("signature_index {} out of bounds (max {})", idx, signatures.len() - 1)
                            ).into());
                        }
                    }
                }
                if let Some(ref tx_part) = serialized.serialized_tx {
                    serialized_tx.extend_from_slice(tx_part);
                }
            }

            // Check request type
            let request_type = tx_request.request_type
                .and_then(|t| tx_request::RequestType::try_from(t).ok())
                .unwrap_or(tx_request::RequestType::Txfinished);

            match request_type {
                tx_request::RequestType::Txfinished => {
                    // Signing complete
                    break;
                }
                tx_request::RequestType::Txinput => {
                    // Device wants an input
                    let details = tx_request.details.as_ref()
                        .ok_or_else(|| DeviceError::ProtobufDecode("Missing details".to_string()))?;
                    let idx = details.request_index.unwrap_or(0) as usize;

                    if idx >= params.inputs.len() {
                        return Err(DeviceError::InvalidInput(
                            format!("request_index {} out of bounds for inputs (len {})", idx, params.inputs.len())
                        ).into());
                    }

                    let tx_ack = self.build_input_ack(&params.inputs[idx], &parsed_inputs[idx])?;
                    let result = self.transport.call(
                        &self.session,
                        MessageType::TxAck as u16,
                        &tx_ack.encode_to_vec(),
                    ).await?;
                    resp_type = result.0;
                    resp_data = result.1;
                }
                tx_request::RequestType::Txoutput => {
                    // Device wants an output
                    let details = tx_request.details.as_ref()
                        .ok_or_else(|| DeviceError::ProtobufDecode("Missing details".to_string()))?;
                    let idx = details.request_index.unwrap_or(0) as usize;

                    if idx >= params.outputs.len() {
                        return Err(DeviceError::InvalidInput(
                            format!("request_index {} out of bounds for outputs (len {})", idx, params.outputs.len())
                        ).into());
                    }

                    let tx_ack = self.build_output_ack(&params.outputs[idx], &parsed_outputs[idx])?;
                    let result = self.transport.call(
                        &self.session,
                        MessageType::TxAck as u16,
                        &tx_ack.encode_to_vec(),
                    ).await?;
                    resp_type = result.0;
                    resp_data = result.1;
                }
                tx_request::RequestType::Txmeta
                | tx_request::RequestType::Txextradata
                | tx_request::RequestType::Txoriginput
                | tx_request::RequestType::Txorigoutput
                | tx_request::RequestType::Txpaymentreq => {
                    // For SegWit inputs, we don't need previous transactions
                    // Return an error if the device requests them
                    return Err(DeviceError::NotSupported(
                        "Previous transaction data not provided (required for non-SegWit inputs)".to_string()
                    ).into());
                }
            }
        }

        Ok(SignedTxResponse {
            signatures,
            serialized_tx: hex::encode(&serialized_tx),
        })
    }

    /// Build TxAck for an input
    fn build_input_ack(
        &self,
        input: &SignTxInput,
        parsed: &(Vec<u32>, ScriptType),
    ) -> Result<protos::bitcoin::TxAck> {
        let prev_hash = hex::decode(&input.prev_hash)
            .map_err(|e| DeviceError::InvalidInput(format!("Invalid prev_hash hex: {}", e)))?;

        let tx_input = tx_ack::transaction_type::TxInputType {
            address_n: parsed.0.clone(),
            prev_hash,
            prev_index: input.prev_index,
            script_sig: None,
            sequence: input.sequence.or(Some(0xFFFFFFFD)), // RBF enabled by default
            script_type: Some(parsed.1 as i32),
            multisig: None,
            amount: Some(input.amount),
            decred_tree: None,
            witness: None,
            ownership_proof: None,
            commitment_data: None,
            orig_hash: None,
            orig_index: None,
            decred_staking_spend: None,
            script_pubkey: None,
            coinjoin_flags: None,
        };

        Ok(protos::bitcoin::TxAck {
            tx: Some(tx_ack::TransactionType {
                version: None,
                inputs: vec![tx_input],
                bin_outputs: vec![],
                lock_time: None,
                outputs: vec![],
                inputs_cnt: None,
                outputs_cnt: None,
                extra_data: None,
                extra_data_len: None,
                expiry: None,
                overwintered: None,
                version_group_id: None,
                timestamp: None,
                branch_id: None,
            }),
        })
    }

    /// Build TxAck for an output
    fn build_output_ack(
        &self,
        output: &SignTxOutput,
        parsed: &Option<(Vec<u32>, ScriptType)>,
    ) -> Result<protos::bitcoin::TxAck> {
        let tx_output = if let Some(ref op_return_data) = output.op_return_data {
            // OP_RETURN output
            let data = hex::decode(op_return_data)
                .map_err(|e| DeviceError::InvalidInput(format!("Invalid op_return_data hex: {}", e)))?;
            tx_ack::transaction_type::TxOutputType {
                address: None,
                address_n: vec![],
                amount: 0,
                script_type: Some(OutputScriptType::PayToOpReturn as i32),
                multisig: None,
                op_return_data: Some(data),
                orig_hash: None,
                orig_index: None,
                payment_req_index: None,
            }
        } else if let Some((path, script_type)) = parsed {
            // Change output (to own address)
            let output_script_type = match script_type {
                ScriptType::SpendAddress => OutputScriptType::PayToAddress,
                ScriptType::SpendP2SHWitness => OutputScriptType::PayToP2SHWitness,
                ScriptType::SpendWitness => OutputScriptType::PayToWitness,
                ScriptType::SpendTaproot => OutputScriptType::PayToTaproot,
                _ => OutputScriptType::PayToAddress,
            };
            tx_ack::transaction_type::TxOutputType {
                address: None,
                address_n: path.clone(),
                amount: output.amount,
                script_type: Some(output_script_type as i32),
                multisig: None,
                op_return_data: None,
                orig_hash: None,
                orig_index: None,
                payment_req_index: None,
            }
        } else if let Some(ref address) = output.address {
            // External output (to address)
            tx_ack::transaction_type::TxOutputType {
                address: Some(address.clone()),
                address_n: vec![],
                amount: output.amount,
                script_type: Some(OutputScriptType::PayToAddress as i32),
                multisig: None,
                op_return_data: None,
                orig_hash: None,
                orig_index: None,
                payment_req_index: None,
            }
        } else {
            return Err(DeviceError::InvalidInput(
                "Output must have either address, path, or op_return_data".to_string()
            ).into());
        };

        Ok(protos::bitcoin::TxAck {
            tx: Some(tx_ack::TransactionType {
                version: None,
                inputs: vec![],
                bin_outputs: vec![],
                lock_time: None,
                outputs: vec![tx_output],
                inputs_cnt: None,
                outputs_cnt: None,
                extra_data: None,
                extra_data_len: None,
                expiry: None,
                overwintered: None,
                version_group_id: None,
                timestamp: None,
                branch_id: None,
            }),
        })
    }

    /// Disconnect from the device.
    pub async fn disconnect(&mut self) -> Result<()> {
        self.transport.release(&self.session).await?;
        Ok(())
    }

    /// Handle potential button request/PIN/passphrase flows.
    ///
    /// Uses a loop instead of recursion to avoid unbounded stack growth
    /// if the device sends many consecutive ButtonRequests.
    async fn handle_response<Resp: Message + Default>(
        &self,
        resp_type: u16,
        resp_data: Vec<u8>,
    ) -> Result<Resp> {
        const MAX_BUTTON_REQUESTS: usize = 64;

        let mut current_type = resp_type;
        let mut current_data = resp_data;

        for _ in 0..MAX_BUTTON_REQUESTS {
            match MessageType::try_from(current_type as i32) {
                Ok(MessageType::Failure) => {
                    let failure = protos::common::Failure::decode(current_data.as_slice())
                        .map_err(|e| DeviceError::ProtobufDecode(e.to_string()))?;
                    return Err(DeviceError::DeviceError {
                        code: failure.code.unwrap_or(0),
                        message: failure.message.unwrap_or_default(),
                    }.into());
                }
                Ok(MessageType::ButtonRequest) => {
                    // Send ButtonAck and loop for the next response
                    let ack = protos::common::ButtonAck {};
                    let (next_type, next_data) = self.transport.call(
                        &self.session,
                        MessageType::ButtonAck as u16,
                        &ack.encode_to_vec(),
                    ).await?;
                    current_type = next_type;
                    current_data = next_data;
                    continue;
                }
                Ok(MessageType::PinMatrixRequest) => {
                    return Err(DeviceError::PinRequired.into());
                }
                Ok(MessageType::PassphraseRequest) => {
                    return Err(DeviceError::PassphraseRequired.into());
                }
                _ => {
                    return Resp::decode(current_data.as_slice())
                        .map_err(|e| DeviceError::ProtobufDecode(e.to_string()).into());
                }
            }
        }

        Err(DeviceError::DeviceError {
            code: 0,
            message: "Too many consecutive ButtonRequests from device".to_string(),
        }.into())
    }
}

impl std::fmt::Debug for ConnectedDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectedDevice")
            .field("info", &self.info)
            .field("session", &self.session)
            .field("features", &self.features)
            .finish()
    }
}

/// Infer script type from BIP32 path.
fn infer_script_type(path: &[u32]) -> ScriptType {
    const HARDENED: u32 = 0x80000000;

    if path.is_empty() {
        return ScriptType::SpendWitness;
    }

    let purpose = path[0] & !HARDENED;
    match purpose {
        44 => ScriptType::SpendAddress,      // Legacy P2PKH
        49 => ScriptType::SpendP2SHWitness,  // Nested SegWit
        84 => ScriptType::SpendWitness,      // Native SegWit
        86 => ScriptType::SpendTaproot,      // Taproot
        _ => ScriptType::SpendWitness,       // Default to native SegWit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infer_script_type() {
        assert_eq!(
            infer_script_type(&[0x8000002C, 0x80000000, 0x80000000, 0, 0]),
            ScriptType::SpendAddress
        );
        assert_eq!(
            infer_script_type(&[0x80000031, 0x80000000, 0x80000000, 0, 0]),
            ScriptType::SpendP2SHWitness
        );
        assert_eq!(
            infer_script_type(&[0x80000054, 0x80000000, 0x80000000, 0, 0]),
            ScriptType::SpendWitness
        );
        assert_eq!(
            infer_script_type(&[0x80000056, 0x80000000, 0x80000000, 0, 0]),
            ScriptType::SpendTaproot
        );
    }
}
