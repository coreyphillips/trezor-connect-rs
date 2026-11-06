//! THP Handshake implementation (Noise XX pattern).
//!
//! Implements the Noise XX handshake pattern for establishing
//! encrypted communication with Trezor devices.

use super::crypto::*;
use super::state::{ThpHandshakeCredentials, ThpPairingMethod, ThpState};
use crate::constants::thp_control;
use crate::error::{Result, ThpError};

/// `trezor_state` values in a handshake completion response.
const STATE_UNPAIRED: u8 = 0;
const STATE_PAIRED: u8 = 1;
const STATE_PAIRED_AUTOCONNECT: u8 = 2;

const AES_GCM_TAG_LENGTH: usize = 16;
const CRC_LENGTH: usize = 4;
/// Masks the sync and ack bits out of a THP control byte.
const CONTROL_TYPE_MASK: u8 = 0xe7;

/// Handshake init request data
#[derive(Debug, Clone)]
pub struct HandshakeInitRequest {
    /// Host ephemeral public key
    pub host_ephemeral_pubkey: [u8; 32],
    /// Try to unlock with stored credentials
    pub try_to_unlock: bool,
}

/// Handshake init response data (from device)
#[derive(Debug, Clone)]
pub struct HandshakeInitResponse {
    /// Trezor ephemeral public key
    pub trezor_ephemeral_pubkey: [u8; 32],
    /// Encrypted Trezor static public key (32 bytes + 16 byte tag)
    pub trezor_encrypted_static_pubkey: Vec<u8>,
    /// Authentication tag
    pub tag: [u8; 16],
}

/// Handshake completion request data
#[derive(Debug, Clone)]
pub struct HandshakeCompletionRequest {
    /// Encrypted host static public key
    pub encrypted_host_static_pubkey: Vec<u8>,
    /// Encrypted payload
    pub encrypted_payload: Vec<u8>,
}

impl HandshakeCompletionRequest {
    /// Whether this request carries a stored credential.
    ///
    /// [`handle_handshake_init`] only includes a credential after it matched the
    /// device's masked static key, so a `true` here means this handshake
    /// authenticated the peer. Without a credential the payload is empty and
    /// encrypts to a bare authentication tag.
    pub fn includes_credential(&self) -> bool {
        self.encrypted_payload.len() > AES_GCM_TAG_LENGTH
    }
}

/// Handshake completion response (from device)
#[derive(Debug, Clone)]
pub struct HandshakeCompletionResponse {
    /// Trezor state (0 = not paired, 1 = paired)
    pub trezor_state: u8,
    /// Available pairing methods
    pub pairing_methods: Vec<ThpPairingMethod>,
}

/// Initialize handshake hash with device properties
pub fn get_handshake_hash(device_properties: &[u8]) -> [u8; 32] {
    // h = SHA-256(protocol_name || device_properties)
    hash_of_two(&protocol_name(), device_properties)
}

/// Stored credentials for reconnection
#[derive(Debug, Clone, Default)]
pub struct StoredCredential {
    /// Host static private key
    pub host_static_key: [u8; 32],
    /// Trezor static public key (for verification)
    pub trezor_static_public_key: [u8; 32],
    /// Credential token
    pub credential: Vec<u8>,
}

/// Verify if stored credentials match the device's handshake response.
///
/// This implements step 10 from the THP spec:
/// Search credentials for pairs (trezor_static_pubkey, credential) such that
/// trezor_masked_static_pubkey == X25519(SHA-256(trezor_static_pubkey || trezor_ephemeral_pubkey), trezor_static_pubkey)
pub fn verify_stored_credential(
    credential: &StoredCredential,
    trezor_masked_static_pubkey: &[u8],
    trezor_ephemeral_pubkey: &[u8; 32],
) -> bool {
    // Compute SHA-256(trezor_static_pubkey || trezor_ephemeral_pubkey)
    let h = hash_of_two(
        &credential.trezor_static_public_key,
        trezor_ephemeral_pubkey,
    );

    // Compute X25519(h, trezor_static_pubkey)
    // h is used as the scalar (private key) for the X25519 operation
    let trezor_static = x25519_dalek::PublicKey::from(credential.trezor_static_public_key);
    let h_secret = x25519_dalek::StaticSecret::from(h);
    let expected = h_secret.diffie_hellman(&trezor_static);

    // Compare with the masked pubkey from device
    expected.as_bytes() == trezor_masked_static_pubkey
}

/// Handle handshake init response
///
/// Processes the response from the device and generates the completion request
/// If stored_credential is provided, it will be used for reconnection instead of pairing
pub fn handle_handshake_init(
    state: &mut ThpState,
    response: &HandshakeInitResponse,
    host_ephemeral_secret: &[u8; 32],
    try_to_unlock: bool,
    stored_credential: Option<&StoredCredential>,
) -> Result<HandshakeCompletionRequest> {
    let handshake_creds = state
        .handshake_credentials()
        .ok_or(ThpError::StateMissing)?;

    let mut h = handshake_creds.handshake_hash.clone();
    let (host_ephemeral_secret, host_ephemeral_pubkey) = keypair_from_secret(host_ephemeral_secret);

    log::debug!("[THP-CRYPTO] Starting handshake init processing");

    // Step 2: h = SHA-256(h || host_ephemeral_pubkey)
    h = hash_of_two(&h, host_ephemeral_pubkey.as_bytes()).to_vec();

    // Step 3: h = SHA-256(h || try_to_unlock)
    h = hash_of_two(&h, &[try_to_unlock as u8]).to_vec();

    // Step 4: h = SHA-256(h || trezor_ephemeral_pubkey)
    h = hash_of_two(&h, &response.trezor_ephemeral_pubkey).to_vec();

    // Step 5: ck, k = HKDF(protocol_name, X25519(host_ephemeral_privkey, trezor_ephemeral_pubkey))
    let trezor_ephemeral_pubkey = x25519_dalek::PublicKey::from(response.trezor_ephemeral_pubkey);
    let shared_secret = x25519_dh(&host_ephemeral_secret, &trezor_ephemeral_pubkey);
    let (mut ck, mut k) = hkdf_derive(&protocol_name(), &shared_secret);
    log::debug!("[THP-CRYPTO] Step 5 key exchange complete");

    // Step 6: Decrypt trezor_masked_static_pubkey
    let iv0 = get_iv_from_nonce(state.send_nonce());
    let trezor_static_pubkey = &response.trezor_encrypted_static_pubkey[..32];
    let trezor_static_tag = &response.trezor_encrypted_static_pubkey[32..48];

    let mut ciphertext_with_tag = trezor_static_pubkey.to_vec();
    ciphertext_with_tag.extend_from_slice(trezor_static_tag);

    let h_array: [u8; 32] = h
        .clone()
        .try_into()
        .map_err(|_| ThpError::HandshakeFailed("Invalid hash length".to_string()))?;
    let trezor_masked_static_pubkey = aes_gcm_decrypt(&k, &iv0, &h_array, &ciphertext_with_tag)?;
    log::debug!("[THP-CRYPTO] Step 6 decrypted masked static pubkey");

    // Step 7: h = SHA-256(h || encrypted_trezor_static_pubkey)
    h = hash_of_two(&h_array, &response.trezor_encrypted_static_pubkey).to_vec();

    // Step 8: ck, k = HKDF(ck, X25519(host_ephemeral_privkey, trezor_masked_static_pubkey))
    let trezor_masked_pubkey_array: [u8; 32] = trezor_masked_static_pubkey
        .try_into()
        .map_err(|_| ThpError::HandshakeFailed("Invalid pubkey length".to_string()))?;
    let trezor_masked_pubkey = x25519_dalek::PublicKey::from(trezor_masked_pubkey_array);
    let shared_secret2 = x25519_dh(&host_ephemeral_secret, &trezor_masked_pubkey);
    let (ck_new, k_new) = hkdf_derive(&ck, &shared_secret2);
    ck = ck_new;
    k = k_new;
    log::debug!("[THP-CRYPTO] Step 8 key derivation complete");

    // Step 9: Verify tag
    let h_array: [u8; 32] = h
        .clone()
        .try_into()
        .map_err(|_| ThpError::HandshakeFailed("Invalid hash length".to_string()))?;
    let mut tag_ciphertext = Vec::new();
    tag_ciphertext.extend_from_slice(&response.tag);
    let _empty = aes_gcm_decrypt(&k, &iv0, &h_array, &tag_ciphertext)?;
    log::debug!("[THP-CRYPTO] Step 9 tag verified successfully");

    // Step 10: h = SHA-256(h || tag)
    h = hash_of_two(&h_array, &response.tag).to_vec();

    // Step 10b: Verify stored credentials match this device
    // If credentials don't match, fall back to new pairing
    let verified_credential = stored_credential.and_then(|stored| {
        log::info!("[THP-CRYPTO] Verifying stored credential against device response...");
        let result = verify_stored_credential(
            stored,
            &trezor_masked_pubkey_array,
            &response.trezor_ephemeral_pubkey,
        );
        log::info!("[THP-CRYPTO] Credential verification result: {}", result);
        if result {
            log::info!("[THP-CRYPTO] Stored credential verified successfully - reconnecting");
            Some(stored)
        } else {
            log::warn!(
                "[THP-CRYPTO] Credential mismatch — stored trezor_pubkey does not match device"
            );
            None
        }
    });

    // Generate host static key (or use existing from verified credentials)
    let static_key: [u8; 32] = if let Some(stored) = verified_credential {
        log::debug!("[THP-CRYPTO] Using stored host static key for reconnection");
        stored.host_static_key
    } else {
        log::debug!("[THP-CRYPTO] Generating new host static key");
        rand::random()
    };
    let (host_static_secret, host_static_pubkey) = keypair_from_secret(&static_key);
    log::debug!("[THP-CRYPTO] Step 11 host static keypair generated");

    // Step 12: encrypted_host_static_pubkey = AES-GCM-ENCRYPT(key=k, IV=0^95 || 1, ad=h, plaintext=host_static_pubkey)
    let iv1 = get_iv_from_nonce(state.recv_nonce());
    let h_array: [u8; 32] = h
        .clone()
        .try_into()
        .map_err(|_| ThpError::HandshakeFailed("Invalid hash length".to_string()))?;
    let encrypted_host_static_pubkey =
        aes_gcm_encrypt(&k, &iv1, &h_array, host_static_pubkey.as_bytes())?;
    log::debug!(
        "[THP-CRYPTO] Step 12 host static pubkey encrypted ({} bytes)",
        encrypted_host_static_pubkey.len()
    );

    // Step 13: h = SHA-256(h || encrypted_host_static_pubkey)
    h = hash_of_two(&h_array, &encrypted_host_static_pubkey).to_vec();

    // Step 14: ck, k = HKDF(ck, X25519(host_static_privkey, trezor_ephemeral_pubkey))
    let shared_secret3 = x25519_dh(&host_static_secret, &trezor_ephemeral_pubkey);
    let (ck_final, k_final) = hkdf_derive(&ck, &shared_secret3);
    log::debug!("[THP-CRYPTO] Step 14 final key derivation complete");

    // Step 15-16: Create encrypted payload (include credential if reconnecting)
    // The payload is a protobuf-encoded ThpHandshakeCompletionReqNoisePayload message
    // with host_pairing_credential as field 1 (bytes)
    let h_array: [u8; 32] = h
        .clone()
        .try_into()
        .map_err(|_| ThpError::HandshakeFailed("Invalid hash length".to_string()))?;
    let payload = if let Some(stored) = verified_credential {
        log::debug!("[THP-CRYPTO] Including verified credential in payload");
        // Encode as protobuf: field 1, wire type 2 (length-delimited)
        // Tag = (field_number << 3) | wire_type = (1 << 3) | 2 = 0x0a
        let mut encoded = vec![0x0a]; // Tag for field 1, length-delimited
        super::pairing_messages::encode_varint(&mut encoded, stored.credential.len() as u64);
        // Add credential data
        encoded.extend_from_slice(&stored.credential);
        encoded
    } else {
        vec![]
    };
    let encrypted_payload = aes_gcm_encrypt(&k_final, &iv0, &h_array, &payload)?;
    log::debug!(
        "[THP-CRYPTO] Step 16 payload encrypted ({} bytes)",
        encrypted_payload.len()
    );

    // HH2 and HH3: Derive final keys
    let (host_key, trezor_key) = hkdf_derive(&ck_final, &[]);
    log::debug!("[THP-CRYPTO] HH2/HH3 session keys derived successfully");

    // Update state with handshake credentials
    let h_final: [u8; 32] = hash_of_two(&h_array, &encrypted_payload);

    let mut new_creds = ThpHandshakeCredentials::default();
    new_creds.handshake_hash = h_final.to_vec();
    new_creds.trezor_encrypted_static_pubkey = response.trezor_encrypted_static_pubkey.clone();
    new_creds.host_encrypted_static_pubkey = encrypted_host_static_pubkey.clone();
    new_creds.static_key = static_key.to_vec();
    new_creds.host_static_public_key = host_static_pubkey.as_bytes().to_vec();
    new_creds.host_key = host_key.to_vec();
    new_creds.trezor_key = trezor_key.to_vec();
    state.set_handshake_credentials(new_creds);

    Ok(HandshakeCompletionRequest {
        encrypted_host_static_pubkey,
        encrypted_payload,
    })
}

/// What the host must do after a handshake completion response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionOutcome {
    /// No credential was sent and the device is unpaired: run code-entry pairing.
    PairingRequired,
    /// The device did not accept the credential that was sent.
    CredentialRejected,
    /// The device accepted the verified credential that was sent.
    CredentialAccepted,
}

/// Decide what a completion response means for this handshake.
///
/// `trezor_state` is a byte chosen by the peer under keys it negotiated itself,
/// so it proves nothing on its own. Only a credential verified against a stored
/// device key authenticates the peer, which is why a paired state without one is
/// an error (THP spec, host state HH3, step 3) and not a reason to skip pairing.
pub fn completion_outcome(trezor_state: u8, credential_sent: bool) -> Result<CompletionOutcome> {
    match (trezor_state, credential_sent) {
        (STATE_UNPAIRED, false) => Ok(CompletionOutcome::PairingRequired),
        (STATE_UNPAIRED, true) => Ok(CompletionOutcome::CredentialRejected),
        (STATE_PAIRED | STATE_PAIRED_AUTOCONNECT, true) => {
            Ok(CompletionOutcome::CredentialAccepted)
        }
        (STATE_PAIRED | STATE_PAIRED_AUTOCONNECT, false) => Err(ThpError::HandshakeFailed(
            "device reported a paired state without a verified credential".to_string(),
        )
        .into()),
        (state, _) => {
            Err(ThpError::HandshakeFailed(format!("device reported invalid state {state}")).into())
        }
    }
}

/// Extract the encrypted payload from a handshake completion response frame.
///
/// Anything else is an error, so that a malformed or unexpected frame can never
/// skip the pairing decision.
pub fn completion_response_payload(frame: &[u8]) -> Result<&[u8]> {
    let unexpected = |reason: String| {
        ThpError::HandshakeFailed(format!(
            "Unexpected response to handshake completion: {reason}"
        ))
    };

    // Header: control(1) + channel(2) + length(2).
    let (&[control, _, _, length_high, length_low], rest) = frame
        .split_first_chunk::<5>()
        .ok_or_else(|| unexpected(format!("{} byte frame", frame.len())))?;
    if control & CONTROL_TYPE_MASK != thp_control::HANDSHAKE_COMP_RES {
        return Err(unexpected(format!("control byte {control:#04x}")).into());
    }

    let length = u16::from_be_bytes([length_high, length_low]) as usize;
    if length <= CRC_LENGTH || rest.len() < length {
        return Err(unexpected(format!(
            "payload length {length} in a {} byte frame",
            frame.len()
        ))
        .into());
    }
    Ok(&rest[..length - CRC_LENGTH])
}

/// Parse handshake completion response
pub fn parse_handshake_completion_response(
    state: &ThpState,
    encrypted_response: &[u8],
) -> Result<HandshakeCompletionResponse> {
    let creds = state
        .handshake_credentials()
        .ok_or(ThpError::StateMissing)?;

    // Decrypt response using trezor_key with empty AAD.
    // This is a post-handshake transport message (not a Noise handshake step),
    // so AAD is empty — consistent with all other encrypt/decrypt operations.
    let iv0 = get_iv_from_nonce(0);
    let trezor_key: [u8; 32] = creds
        .trezor_key
        .clone()
        .try_into()
        .map_err(|_| ThpError::HandshakeFailed("Invalid trezor key".to_string()))?;

    let decrypted = aes_gcm_decrypt(&trezor_key, &iv0, &[], encrypted_response)?;

    // The device sends trezor_state as a raw byte (not protobuf-encoded).
    // The encrypted payload is 1 byte ciphertext + 16 byte GCM tag.
    // After decryption we get a single byte: 0=needs pairing, 1=paired, 2=autoconnect.
    // Pairing methods come from ThpDeviceProperties in channel allocation, not here.
    let trezor_state = if decrypted.is_empty() {
        0u8
    } else {
        decrypted[0]
    };

    Ok(HandshakeCompletionResponse {
        trezor_state,
        pairing_methods: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_handshake_hash() {
        let device_props = b"test device";
        let hash = get_handshake_hash(device_props);
        assert_eq!(hash.len(), 32);
    }

    /// Helper: create a ThpState with given trezor_key and handshake_hash,
    /// and encrypt `plaintext` with those credentials (nonce=0, AAD=handshake_hash).
    fn make_encrypted_completion(plaintext: &[u8]) -> (ThpState, Vec<u8>) {
        let key = [0x42u8; 32];

        let mut creds = ThpHandshakeCredentials::default();
        creds.trezor_key = key.to_vec();
        creds.handshake_hash = vec![0xAB; 32];

        let mut state = ThpState::new();
        state.set_handshake_credentials(creds);

        let iv = get_iv_from_nonce(0);
        let encrypted = aes_gcm_encrypt(&key, &iv, &[], plaintext).unwrap();
        (state, encrypted)
    }

    #[test]
    fn completion_outcome_requires_a_credential_for_a_paired_state() {
        use CompletionOutcome::*;

        for (state, credential_sent, expected) in [
            (0, false, Some(PairingRequired)),
            (0, true, Some(CredentialRejected)),
            (1, true, Some(CredentialAccepted)),
            (2, true, Some(CredentialAccepted)),
            (1, false, None),
            (2, false, None),
            (3, false, None),
            (3, true, None),
            (255, true, None),
        ] {
            let outcome = completion_outcome(state, credential_sent).ok();
            assert_eq!(
                outcome, expected,
                "state={state} credential={credential_sent}"
            );
        }
    }

    #[test]
    fn rejected_states_do_not_trigger_handshake_retries() {
        // perform_thp_handshake retries on these substrings and then clears the
        // stored credential, which a peer's reported state must not be able to cause.
        for (state, credential_sent) in [(1, false), (3, true)] {
            let error = completion_outcome(state, credential_sent)
                .unwrap_err()
                .to_string();
            assert!(!error.contains("Unexpected response"), "{error}");
            assert!(!error.contains("CredentialRejected"), "{error}");
        }
    }

    #[test]
    fn completion_response_payload_accepts_a_well_formed_frame() {
        let mut frame = vec![thp_control::HANDSHAKE_COMP_RES, 0x12, 0x34, 0x00, 0x07];
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0, 0, 0, 0]);
        assert_eq!(
            completion_response_payload(&frame).unwrap(),
            &[0xaa, 0xbb, 0xcc]
        );

        // The sync and ack bits are not part of the control type.
        frame[0] |= 0x18;
        assert!(completion_response_payload(&frame).is_ok());
    }

    #[test]
    fn completion_response_payload_rejects_malformed_frames() {
        let comp = thp_control::HANDSHAKE_COMP_RES;
        for frame in [
            vec![],
            vec![comp, 0x12, 0x34],
            vec![comp, 0x12, 0x34, 0x00],
            // Only a CRC.
            vec![comp, 0x12, 0x34, 0x00, 0x04, 0, 0, 0, 0],
            // Declares more than it holds.
            vec![comp, 0x12, 0x34, 0x00, 0xff, 0, 0, 0, 0, 0],
            // Some other message.
            vec![
                thp_control::ENCRYPTED,
                0x12,
                0x34,
                0x00,
                0x05,
                1,
                0,
                0,
                0,
                0,
            ],
        ] {
            let error = completion_response_payload(&frame).unwrap_err();
            assert!(error.to_string().contains("Unexpected response"), "{error}");
        }
    }

    #[test]
    fn empty_payload_is_not_a_credential_but_any_credential_is() {
        let request_with_payload_of = |length: usize| HandshakeCompletionRequest {
            encrypted_host_static_pubkey: vec![0; 48],
            encrypted_payload: vec![0; length],
        };
        assert!(!request_with_payload_of(AES_GCM_TAG_LENGTH).includes_credential());
        assert!(request_with_payload_of(AES_GCM_TAG_LENGTH + 2).includes_credential());
    }

    #[test]
    fn test_parse_completion_response_empty() {
        let (state, encrypted) = make_encrypted_completion(&[]);
        let result = parse_handshake_completion_response(&state, &encrypted).unwrap();
        assert_eq!(result.trezor_state, 0);
        assert!(result.pairing_methods.is_empty());
    }

    #[test]
    fn test_parse_completion_response_state_not_paired() {
        // Raw byte 0x00 = needs pairing
        let (state, encrypted) = make_encrypted_completion(&[0x00]);
        let result = parse_handshake_completion_response(&state, &encrypted).unwrap();
        assert_eq!(result.trezor_state, 0);
        assert!(result.pairing_methods.is_empty());
    }

    #[test]
    fn test_parse_completion_response_state_paired() {
        // Raw byte 0x01 = paired
        let (state, encrypted) = make_encrypted_completion(&[0x01]);
        let result = parse_handshake_completion_response(&state, &encrypted).unwrap();
        assert_eq!(result.trezor_state, 1);
        assert!(result.pairing_methods.is_empty());
    }

    #[test]
    fn test_parse_completion_response_state_autoconnect() {
        // Raw byte 0x02 = autoconnect
        let (state, encrypted) = make_encrypted_completion(&[0x02]);
        let result = parse_handshake_completion_response(&state, &encrypted).unwrap();
        assert_eq!(result.trezor_state, 2);
        assert!(result.pairing_methods.is_empty());
    }
}
