//! `CallbackTransport` handshake tests against a simulated THP peer.
//!
//! `SimulatedPeer` runs the responder side of the THP handshake with real
//! cryptography and keys of its own. It follows the spec by default, reporting a
//! paired state only for a credential it issued, and each test can change how it
//! answers the completion request.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use num_bigint::BigUint;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::constants::{message_type, thp_control, thp_message_type, thp_pairing_method};
use crate::error::Result;
use crate::protocol::thp::StoredCredential;
use crate::protocol::thp::crypto::{
    aes_gcm_decrypt, aes_gcm_encrypt, crc32, get_iv_from_nonce, hash_of_two, hkdf_derive,
    keypair_from_secret, protocol_name, sha256, x25519_dh,
};
use crate::protocol::thp::get_handshake_hash;
use crate::protocol::thp::pairing_messages::encode_varint;
use crate::transport::callback::{
    CallbackDeviceInfo, CallbackReadResult, CallbackResult, CallbackTransport,
    StoredCredentialJson, TransportCallback,
};
use crate::transport::traits::Transport;

const PATH: &str = "ble:simulated";
const PASSPHRASE: &str = "hidden-wallet-passphrase";
const CHANNEL: [u8; 2] = [0x12, 0x34];
const DEVICE_PROPERTIES: &[u8] = b"simulated-device-properties";
const ISSUED_CREDENTIAL: &[u8] = b"credential-issued-by-this-device";

/// How the peer answers the handshake completion request.
#[derive(Clone, Copy)]
enum CompletionReply {
    /// Report paired only for the credential this peer issued, as the spec requires.
    FollowSpec,
    /// Report this state regardless of what the host sent.
    ClaimState(u8),
    /// A well-formed frame with a control byte that is not a completion response.
    WrongControlByte,
    /// A completion response whose payload holds only the CRC.
    PayloadOnlyCrc,
    /// A frame too short to contain a THP length field.
    TruncatedFrame,
}

/// What the user types when the app asks for a pairing code.
#[derive(Clone, Copy)]
enum UserCode {
    /// The code on the device's screen.
    Displayed,
    /// A code that does not match the screen.
    Wrong,
    /// The user cancels because no code was shown.
    Cancels,
}

/// Noise state for the channel in progress.
#[derive(Default)]
struct Channel {
    ephemeral_secret: Option<StaticSecret>,
    chaining_key: [u8; 32],
    key: [u8; 32],
    hash: [u8; 32],
    host_key: [u8; 32],
    trezor_key: [u8; 32],
    recv_nonce: u32,
    send_nonce: u32,
    pairing_secret: [u8; 32],
    challenge: Vec<u8>,
}

#[derive(Default)]
struct Observed {
    channel_allocations: usize,
    credentials_received: Vec<Vec<u8>>,
    code_prompts: usize,
    session_requests: Vec<Vec<u8>>,
    credential_saves: usize,
}

struct SimulatedPeer {
    static_secret: StaticSecret,
    static_public: PublicKey,
    reply: CompletionReply,
    user_code: UserCode,
    stored_credential: Mutex<Option<String>>,
    outbox: Mutex<VecDeque<Vec<u8>>>,
    channel: Mutex<Channel>,
    observed: Mutex<Observed>,
}

impl SimulatedPeer {
    fn new(reply: CompletionReply) -> Arc<Self> {
        Self::with_user_code(reply, UserCode::Displayed)
    }

    fn with_user_code(reply: CompletionReply, user_code: UserCode) -> Arc<Self> {
        let (static_secret, static_public) = keypair_from_secret(&rand::random());
        Arc::new(Self {
            static_secret,
            static_public,
            reply,
            user_code,
            stored_credential: Mutex::new(None),
            outbox: Mutex::new(VecDeque::new()),
            channel: Mutex::new(Channel::default()),
            observed: Mutex::new(Observed::default()),
        })
    }

    /// Store a credential on the host, as a previous pairing would have.
    fn store_credential(&self, trezor_static_public_key: [u8; 32], credential: &[u8]) {
        let stored = StoredCredential {
            host_static_key: rand::random(),
            trezor_static_public_key,
            credential: credential.to_vec(),
        };
        let json = serde_json::to_string(&StoredCredentialJson::from(&stored)).unwrap();
        *self.stored_credential.lock().unwrap() = Some(json);
    }

    fn store_credential_this_device_issued(&self) {
        self.store_credential(self.static_public.to_bytes(), ISSUED_CREDENTIAL);
    }

    fn store_credential_for_another_device(&self) {
        let (_, other_public) = keypair_from_secret(&rand::random());
        self.store_credential(other_public.to_bytes(), ISSUED_CREDENTIAL);
    }

    fn handle_frame(&self, frame: &[u8]) {
        let length = u16::from_be_bytes([frame[3], frame[4]]) as usize;
        let payload = &frame[5..5 + length - 4];
        match frame[0] & 0xe7 {
            thp_control::CHANNEL_ALLOCATION_REQ => self.allocate_channel(payload),
            thp_control::HANDSHAKE_INIT_REQ => self.answer_init(payload),
            thp_control::HANDSHAKE_COMP_REQ => self.answer_completion(payload),
            thp_control::ENCRYPTED => self.answer_encrypted(payload),
            _ => {} // ACKs need no answer.
        }
    }

    fn allocate_channel(&self, nonce: &[u8]) {
        self.observed.lock().unwrap().channel_allocations += 1;
        *self.channel.lock().unwrap() = Channel::default();
        let mut payload = nonce.to_vec();
        payload.extend_from_slice(&CHANNEL);
        payload.extend_from_slice(DEVICE_PROPERTIES);
        self.send(thp_control::CHANNEL_ALLOCATION_RES, [0xff, 0xff], &payload);
    }

    fn answer_init(&self, request: &[u8]) {
        let host_ephemeral: [u8; 32] = request[..32].try_into().unwrap();
        let host_ephemeral = PublicKey::from(host_ephemeral);
        let (ephemeral_secret, ephemeral_public) = keypair_from_secret(&rand::random());

        let mut hash = get_handshake_hash(DEVICE_PROPERTIES);
        hash = hash_of_two(&hash, host_ephemeral.as_bytes());
        hash = hash_of_two(&hash, &request[32..33]);
        hash = hash_of_two(&hash, ephemeral_public.as_bytes());

        let shared = x25519_dh(&ephemeral_secret, &host_ephemeral);
        let (chaining_key, key) = hkdf_derive(&protocol_name(), &shared);

        let mask = StaticSecret::from(hash_of_two(
            self.static_public.as_bytes(),
            ephemeral_public.as_bytes(),
        ));
        let masked_static = x25519_dh(&mask, &self.static_public);
        let iv0 = get_iv_from_nonce(0);
        let encrypted_static = aes_gcm_encrypt(&key, &iv0, &hash, &masked_static).unwrap();
        hash = hash_of_two(&hash, &encrypted_static);

        let unmasked = x25519_dh(&self.static_secret, &host_ephemeral);
        let shared = x25519_dh(&mask, &PublicKey::from(unmasked));
        let (chaining_key, key) = hkdf_derive(&chaining_key, &shared);
        let tag = aes_gcm_encrypt(&key, &iv0, &hash, &[]).unwrap();
        hash = hash_of_two(&hash, &tag);

        let mut payload = ephemeral_public.as_bytes().to_vec();
        payload.extend_from_slice(&encrypted_static);
        payload.extend_from_slice(&tag);
        self.send(thp_control::HANDSHAKE_INIT_RES, CHANNEL, &payload);

        let mut channel = self.channel.lock().unwrap();
        channel.ephemeral_secret = Some(ephemeral_secret);
        channel.chaining_key = chaining_key;
        channel.key = key;
        channel.hash = hash;
    }

    fn answer_completion(&self, request: &[u8]) {
        let credential = {
            let mut channel = self.channel.lock().unwrap();
            let (encrypted_host_static, encrypted_payload) = request.split_at(48);

            let host_static = aes_gcm_decrypt(
                &channel.key,
                &get_iv_from_nonce(1),
                &channel.hash,
                encrypted_host_static,
            )
            .unwrap();
            let host_static: [u8; 32] = host_static.try_into().unwrap();
            let hash = hash_of_two(&channel.hash, encrypted_host_static);

            let shared = x25519_dh(
                channel.ephemeral_secret.as_ref().unwrap(),
                &PublicKey::from(host_static),
            );
            let (chaining_key, key) = hkdf_derive(&channel.chaining_key, &shared);
            let plaintext =
                aes_gcm_decrypt(&key, &get_iv_from_nonce(0), &hash, encrypted_payload).unwrap();

            channel.hash = hash_of_two(&hash, encrypted_payload);
            (channel.host_key, channel.trezor_key) = hkdf_derive(&chaining_key, &[]);
            channel.send_nonce = 1;

            // Field 1 of the protobuf payload, when the host sent a credential.
            plaintext.get(2..).map(<[u8]>::to_vec)
        };

        let is_issued = credential.as_deref() == Some(ISSUED_CREDENTIAL);
        if let Some(credential) = credential {
            self.observed
                .lock()
                .unwrap()
                .credentials_received
                .push(credential);
        }

        let state = match self.reply {
            CompletionReply::FollowSpec => is_issued as u8,
            CompletionReply::ClaimState(state) => state,
            CompletionReply::WrongControlByte => {
                return self.send(thp_control::ENCRYPTED, CHANNEL, &[0u8; 32]);
            }
            CompletionReply::PayloadOnlyCrc => {
                return self.send(thp_control::HANDSHAKE_COMP_RES, CHANNEL, &[]);
            }
            CompletionReply::TruncatedFrame => {
                let frame = vec![thp_control::HANDSHAKE_COMP_RES, CHANNEL[0], CHANNEL[1]];
                return self.outbox.lock().unwrap().push_back(frame);
            }
        };

        let trezor_key = self.channel.lock().unwrap().trezor_key;
        let encrypted_state =
            aes_gcm_encrypt(&trezor_key, &get_iv_from_nonce(0), &[], &[state]).unwrap();
        self.send(thp_control::HANDSHAKE_COMP_RES, CHANNEL, &encrypted_state);
    }

    fn answer_encrypted(&self, ciphertext: &[u8]) {
        let plaintext = {
            let mut channel = self.channel.lock().unwrap();
            let iv = get_iv_from_nonce(channel.recv_nonce);
            channel.recv_nonce += 1;
            aes_gcm_decrypt(&channel.host_key, &iv, &[], ciphertext).unwrap()
        };
        let session_id = plaintext[0];
        let request_type = u16::from_be_bytes([plaintext[1], plaintext[2]]);
        let (response_type, response) = self.respond_to_message(request_type, &plaintext[3..]);

        let mut message = vec![session_id];
        message.extend_from_slice(&response_type.to_be_bytes());
        message.extend_from_slice(&response);
        let encrypted = {
            let mut channel = self.channel.lock().unwrap();
            let iv = get_iv_from_nonce(channel.send_nonce);
            channel.send_nonce += 1;
            aes_gcm_encrypt(&channel.trezor_key, &iv, &[], &message).unwrap()
        };
        self.send(thp_control::ENCRYPTED, CHANNEL, &encrypted);
    }

    fn respond_to_message(&self, request_type: u16, data: &[u8]) -> (u16, Vec<u8>) {
        use thp_message_type::*;

        let mut channel = self.channel.lock().unwrap();
        match request_type {
            THP_PAIRING_REQUEST => (THP_PAIRING_REQUEST_APPROVED, vec![]),
            THP_SELECT_METHOD => {
                channel.pairing_secret = rand::random();
                (
                    THP_CODE_ENTRY_COMMITMENT,
                    length_delimited(0x0a, &sha256(&channel.pairing_secret)),
                )
            }
            THP_CODE_ENTRY_CHALLENGE => {
                channel.challenge = data[2..].to_vec();
                (
                    THP_CODE_ENTRY_CPACE_TREZOR,
                    length_delimited(0x0a, &[0x42; 32]),
                )
            }
            THP_CODE_ENTRY_CPACE_HOST_TAG => (
                THP_CODE_ENTRY_SECRET,
                length_delimited(0x0a, &channel.pairing_secret),
            ),
            THP_CREDENTIAL_REQUEST => {
                let mut response = length_delimited(0x0a, self.static_public.as_bytes());
                response.extend(length_delimited(0x12, ISSUED_CREDENTIAL));
                (THP_CREDENTIAL_RESPONSE, response)
            }
            THP_END_REQUEST => (THP_END_RESPONSE, vec![]),
            THP_CREATE_NEW_SESSION => {
                self.observed
                    .lock()
                    .unwrap()
                    .session_requests
                    .push(data.to_vec());
                (message_type::SUCCESS, vec![])
            }
            _ => (message_type::FAILURE, vec![]),
        }
    }

    fn displayed_code(&self) -> String {
        let channel = self.channel.lock().unwrap();
        let mut input = vec![thp_pairing_method::CODE_ENTRY];
        input.extend_from_slice(&channel.hash);
        input.extend_from_slice(&channel.pairing_secret);
        input.extend_from_slice(&channel.challenge);
        let code = BigUint::from_bytes_be(&sha256(&input)) % BigUint::from(1_000_000u32);
        format!("{code:0>6}")
    }

    fn send(&self, control: u8, channel: [u8; 2], payload: &[u8]) {
        let mut frame = vec![control, channel[0], channel[1]];
        frame.extend_from_slice(&((payload.len() + 4) as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        let crc = crc32(&frame);
        frame.extend_from_slice(&crc);
        self.outbox.lock().unwrap().push_back(frame);
    }

    fn observed<T>(&self, read: impl FnOnce(&Observed) -> T) -> T {
        read(&self.observed.lock().unwrap())
    }

    fn assert_received_no_session_request(&self) {
        assert!(
            self.observed(|o| o.session_requests.is_empty()),
            "an unverified peer reached session creation and received the passphrase"
        );
    }

    fn assert_received_passphrase_once(&self) {
        let requests = self.observed(|o| o.session_requests.clone());
        assert_eq!(requests.len(), 1, "expected exactly one session request");
        let sent = String::from_utf8_lossy(&requests[0]);
        assert!(sent.contains(PASSPHRASE));
    }
}

fn ok() -> CallbackResult {
    CallbackResult {
        success: true,
        error: String::new(),
    }
}

fn length_delimited(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut encoded = vec![tag];
    encode_varint(&mut encoded, value.len() as u64);
    encoded.extend_from_slice(value);
    encoded
}

impl TransportCallback for SimulatedPeer {
    fn enumerate_devices(&self) -> Vec<CallbackDeviceInfo> {
        vec![]
    }

    fn open_device(&self, _path: &str) -> CallbackResult {
        ok()
    }

    fn close_device(&self, _path: &str) -> CallbackResult {
        self.outbox.lock().unwrap().clear();
        ok()
    }

    fn read_chunk(&self, _path: &str) -> CallbackReadResult {
        match self.outbox.lock().unwrap().pop_front() {
            Some(data) => CallbackReadResult {
                success: true,
                data,
                error: String::new(),
            },
            None => CallbackReadResult {
                success: false,
                data: vec![],
                error: "no data".to_string(),
            },
        }
    }

    fn write_chunk(&self, _path: &str, data: &[u8]) -> CallbackResult {
        self.handle_frame(data);
        ok()
    }

    // Large enough that no message in these tests is split into chunks.
    fn get_chunk_size(&self, _path: &str) -> u32 {
        1024
    }

    fn get_pairing_code(&self) -> String {
        self.observed.lock().unwrap().code_prompts += 1;
        match self.user_code {
            UserCode::Displayed => self.displayed_code(),
            UserCode::Wrong => {
                let displayed: u32 = self.displayed_code().parse().unwrap();
                format!("{:0>6}", (displayed + 1) % 1_000_000)
            }
            UserCode::Cancels => String::new(),
        }
    }

    fn save_thp_credential(&self, _device_id: &str, credential_json: &str) -> bool {
        self.observed.lock().unwrap().credential_saves += 1;
        *self.stored_credential.lock().unwrap() = Some(credential_json.to_string());
        true
    }

    fn load_thp_credential(&self, _device_id: &str) -> Option<String> {
        self.stored_credential
            .lock()
            .unwrap()
            .clone()
            .filter(|json| !json.is_empty())
    }
}

async fn acquire(peer: &Arc<SimulatedPeer>) -> Result<String> {
    CallbackTransport::new(peer.clone())
        .with_session_passphrase(PASSPHRASE.to_string(), false)
        .acquire(PATH, None)
        .await
}

// Genuine device behaviour must not change.

#[tokio::test]
async fn fresh_pairing_asks_for_the_code_then_creates_a_session() {
    let peer = SimulatedPeer::new(CompletionReply::FollowSpec);

    acquire(&peer).await.unwrap();

    assert_eq!(peer.observed(|o| o.code_prompts), 1);
    assert_eq!(peer.observed(|o| o.credential_saves), 1);
    peer.assert_received_passphrase_once();
}

#[tokio::test]
async fn valid_stored_credential_reconnects_without_a_code() {
    for reply in [
        CompletionReply::FollowSpec,
        CompletionReply::ClaimState(2), // autoconnect
    ] {
        let peer = SimulatedPeer::new(reply);
        peer.store_credential_this_device_issued();

        acquire(&peer).await.unwrap();

        assert_eq!(
            peer.observed(|o| o.credentials_received.clone()),
            vec![ISSUED_CREDENTIAL.to_vec()]
        );
        assert_eq!(peer.observed(|o| o.code_prompts), 0);
        peer.assert_received_passphrase_once();
    }
}

#[tokio::test]
async fn credential_for_another_device_falls_back_to_fresh_pairing() {
    let peer = SimulatedPeer::new(CompletionReply::FollowSpec);
    peer.store_credential_for_another_device();

    acquire(&peer).await.unwrap();

    assert!(peer.observed(|o| o.credentials_received.is_empty()));
    assert_eq!(peer.observed(|o| o.code_prompts), 1);
    peer.assert_received_passphrase_once();
}

#[tokio::test]
async fn credential_the_device_rejects_falls_back_to_fresh_pairing() {
    let peer = SimulatedPeer::new(CompletionReply::FollowSpec);
    peer.store_credential(peer.static_public.to_bytes(), b"revoked-credential");

    acquire(&peer).await.unwrap();

    assert_eq!(peer.observed(|o| o.code_prompts), 1);
    peer.assert_received_passphrase_once();
}

// An unverified peer must not reach session creation.

#[tokio::test]
async fn paired_claim_without_a_credential_is_rejected() {
    for claimed_state in [1, 2] {
        let peer = SimulatedPeer::new(CompletionReply::ClaimState(claimed_state));

        let error = acquire(&peer).await.unwrap_err();

        assert!(error.to_string().contains("Handshake failed"), "{error}");
        assert_eq!(peer.observed(|o| o.code_prompts), 0);
        peer.assert_received_no_session_request();
    }
}

#[tokio::test]
async fn paired_claim_is_not_retried_and_keeps_the_stored_credential() {
    let peer = SimulatedPeer::new(CompletionReply::ClaimState(1));
    peer.store_credential_for_another_device();

    acquire(&peer).await.unwrap_err();

    assert!(
        peer.observed(|o| o.credentials_received.is_empty()),
        "a credential must never be sent to a peer with a different key"
    );
    assert_eq!(peer.observed(|o| o.channel_allocations), 1);
    assert!(
        peer.observed(|o| o.credential_saves) == 0,
        "a rejected paired state must not erase the stored credential"
    );
    peer.assert_received_no_session_request();
}

#[tokio::test]
async fn unknown_state_is_rejected_even_with_a_verified_credential() {
    for store_credential in [false, true] {
        let peer = SimulatedPeer::new(CompletionReply::ClaimState(3));
        if store_credential {
            peer.store_credential_this_device_issued();
        }

        acquire(&peer).await.unwrap_err();

        assert_eq!(peer.observed(|o| o.channel_allocations), 1);
        peer.assert_received_no_session_request();
    }
}

#[tokio::test]
async fn unexpected_completion_control_byte_is_rejected() {
    let peer = SimulatedPeer::new(CompletionReply::WrongControlByte);

    acquire(&peer).await.unwrap_err();

    peer.assert_received_no_session_request();
}

#[tokio::test]
async fn completion_payload_with_only_a_crc_is_rejected() {
    let peer = SimulatedPeer::new(CompletionReply::PayloadOnlyCrc);

    acquire(&peer).await.unwrap_err();

    peer.assert_received_no_session_request();
}

#[tokio::test]
async fn truncated_completion_frame_is_rejected_without_panicking() {
    let peer = SimulatedPeer::new(CompletionReply::TruncatedFrame);

    acquire(&peer).await.unwrap_err();

    peer.assert_received_no_session_request();
}

// A peer that asks for pairing still has to pass it.

#[tokio::test]
async fn peer_cannot_pass_pairing_when_the_user_has_no_code() {
    let peer = SimulatedPeer::with_user_code(CompletionReply::FollowSpec, UserCode::Cancels);

    acquire(&peer).await.unwrap_err();

    assert!(peer.observed(|o| o.code_prompts) >= 1);
    peer.assert_received_no_session_request();
}

#[tokio::test]
async fn wrong_pairing_code_does_not_create_a_session() {
    let peer = SimulatedPeer::with_user_code(CompletionReply::FollowSpec, UserCode::Wrong);

    acquire(&peer).await.unwrap_err();

    assert!(peer.observed(|o| o.code_prompts) >= 1);
    peer.assert_received_no_session_request();
}
