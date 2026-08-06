use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::SharedSecret;

/// HKDF-SHA256 salt for deriving the two directional session keys from the
/// X25519 shared secret. Fixed and public (salts don't need to be secret) —
/// only present to domain-separate this derivation from any other use of
/// the same shared-secret-producing key exchange.
pub const HKDF_SALT: &[u8] = b"orosu-e2e-v2-salt";
/// HKDF `info` label for the client-to-server directional key. Must match
/// byte-for-byte in client/src/handshake.js.
pub const HKDF_INFO_CLIENT_TO_SERVER: &[u8] = b"orosu-e2e-v2 client-to-server";
/// HKDF `info` label for the server-to-client directional key. Must match
/// byte-for-byte in client/src/handshake.js.
pub const HKDF_INFO_SERVER_TO_CLIENT: &[u8] = b"orosu-e2e-v2 server-to-client";
/// AEAD associated data for the key-confirmation frame, binding it to its
/// purpose so it can't be confused with (or replayed as) any other
/// encrypted-empty-plaintext frame.
pub const CONFIRMATION_AAD: &[u8] = b"orosu-e2e-v2-server-confirm";
/// Size in bytes of the raw ClientHello frame (an X25519 public key).
pub const CLIENT_HELLO_LEN: usize = 32;
/// Size in bytes of the ServerConfirm frame: an empty plaintext sealed with
/// ChaCha20-Poly1305 is exactly its 16-byte authentication tag.
pub const CONFIRMATION_FRAME_LEN: usize = 16;

/// A ChaCha20-Poly1305 key plus a strictly monotonic nonce counter for one
/// direction of a connection. Nonces are never sent on the wire — both
/// sides derive them purely from how many frames they've sent/received in
/// this direction, which is well-defined because WebSocket-over-TCP is
/// ordered and reliable. This also gives replay protection for free: a
/// replayed or reordered frame is decrypted against whatever nonce the
/// counter has since advanced to, which won't match how it was actually
/// encrypted, so the authentication tag fails.
///
/// `u64::MAX` is reserved as an "exhausted" sentinel rather than a usable
/// counter value, so seal/open fail cleanly instead of silently wrapping
/// the nonce back to a previously-used value.
struct DirectionalCipher {
    cipher: ChaCha20Poly1305,
    counter: u64,
}

impl DirectionalCipher {
    fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(&Key::from(key)),
            counter: 0,
        }
    }

    fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> anyhow::Result<Vec<u8>> {
        if self.counter == u64::MAX {
            return Err(anyhow::anyhow!(
                "nonce counter exhausted; connection must be re-established"
            ));
        }
        let nonce = nonce_for(self.counter);
        let ciphertext = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("encryption failed"))?;
        self.counter += 1;
        Ok(ciphertext)
    }

    fn open(&mut self, ciphertext: &[u8], aad: &[u8]) -> anyhow::Result<Vec<u8>> {
        if self.counter == u64::MAX {
            return Err(anyhow::anyhow!(
                "nonce counter exhausted; connection must be re-established"
            ));
        }
        let nonce = nonce_for(self.counter);
        let plaintext = self
            .cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("decryption failed"))?;
        self.counter += 1;
        Ok(plaintext)
    }
}

fn nonce_for(counter: u64) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[4..].copy_from_slice(&counter.to_be_bytes());
    Nonce::from(bytes)
}

fn derive_directional_keys(shared_secret: &SharedSecret) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_secret.as_bytes());
    let mut client_to_server = [0u8; 32];
    let mut server_to_client = [0u8; 32];
    hk.expand(HKDF_INFO_CLIENT_TO_SERVER, &mut client_to_server)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    hk.expand(HKDF_INFO_SERVER_TO_CLIENT, &mut server_to_client)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    (client_to_server, server_to_client)
}

/// Both directional ciphers for one end of an established v2 connection,
/// always named from this party's own point of view: `send` is the
/// direction this party writes with, `recv` is the direction it reads with.
/// There is deliberately no boolean "is_server" flag threaded through
/// call sites — the ambiguity collapses into which of the two constructors
/// below gets called, at the one place where the role is already known.
pub struct SessionKeys {
    send: DirectionalCipher,
    recv: DirectionalCipher,
}

/// Rejects a non-contributory shared secret (the peer supplied a low-order
/// public key, e.g. all-zero, to force a fixed, publicly-known shared
/// secret — see `SharedSecret::was_contributory`'s docs) before it can ever
/// reach key derivation. Called from both `derive_for_server` and
/// `derive_for_client` rather than threading a role flag through one shared
/// function — see the `SessionKeys` doc comment on why that distinction is
/// kept out of this module's internals, not just its public API.
fn require_contributory(shared_secret: &SharedSecret) -> anyhow::Result<()> {
    if !shared_secret.was_contributory() {
        anyhow::bail!(
            "ECDH shared secret was non-contributory (peer supplied a low-order public key)"
        );
    }
    Ok(())
}

impl SessionKeys {
    /// Derives session keys for the server's side of a connection: this
    /// party sends with the server-to-client key and receives with the
    /// client-to-server key.
    ///
    /// Errors if `shared_secret` is non-contributory — see
    /// `require_contributory`. This is the ADT enforcement of that check:
    /// there is no way to obtain a `SessionKeys` from a bad shared secret,
    /// so every call site is forced to handle the failure rather than one
    /// being able to forget the check.
    pub fn derive_for_server(shared_secret: &SharedSecret) -> anyhow::Result<Self> {
        require_contributory(shared_secret)?;
        let (client_to_server, server_to_client) = derive_directional_keys(shared_secret);
        Ok(Self {
            send: DirectionalCipher::new(server_to_client),
            recv: DirectionalCipher::new(client_to_server),
        })
    }

    /// Derives session keys for the client's side of a connection: this
    /// party sends with the client-to-server key and receives with the
    /// server-to-client key. Same non-contributory check as
    /// `derive_for_server` — see its docs.
    pub fn derive_for_client(shared_secret: &SharedSecret) -> anyhow::Result<Self> {
        require_contributory(shared_secret)?;
        let (client_to_server, server_to_client) = derive_directional_keys(shared_secret);
        Ok(Self {
            send: DirectionalCipher::new(client_to_server),
            recv: DirectionalCipher::new(server_to_client),
        })
    }
}

/// Whether a connection's application-layer bytes are additionally
/// AEAD-sealed beneath the existing envelope layer. This is the type that
/// makes "send a plaintext envelope on what should be an encrypted
/// connection" structurally unrepresentable: `seal`/`open` are the only way
/// to move bytes through it, and the `Plaintext` variant carries no key
/// material to accidentally reuse or leak.
pub enum ConnectionSecurity {
    /// Protocol version 0 or 1: no handshake happened, bytes pass through
    /// completely unchanged — this is what keeps every existing client
    /// working byte-for-byte after a server upgrade.
    Plaintext,
    /// Protocol version 2: bytes are ChaCha20-Poly1305 sealed/opened using
    /// the session keys derived during the handshake.
    Encrypted(SessionKeys),
}

impl ConnectionSecurity {
    pub fn seal(&mut self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self {
            ConnectionSecurity::Plaintext => Ok(plaintext.to_vec()),
            ConnectionSecurity::Encrypted(keys) => keys.send.seal(plaintext, b""),
        }
    }

    pub fn open(&mut self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self {
            ConnectionSecurity::Plaintext => Ok(ciphertext.to_vec()),
            ConnectionSecurity::Encrypted(keys) => keys.recv.open(ciphertext, b""),
        }
    }
}

/// Builds the ServerConfirm frame: an empty plaintext sealed with the
/// server-to-client key, bound to `CONFIRMATION_AAD`. Consumes send-counter
/// value 0, so the first real response envelope after this uses counter 1.
/// Serves as key confirmation — a client that verifies this frame knows the
/// server actually holds the private key matching the `server_key` it
/// pinned, not just that *some* peer answered on the socket.
pub fn build_confirmation_frame(
    session_keys: &mut SessionKeys,
) -> anyhow::Result<[u8; CONFIRMATION_FRAME_LEN]> {
    let sealed = session_keys.send.seal(&[], CONFIRMATION_AAD)?;
    sealed
        .try_into()
        .map_err(|_| anyhow::anyhow!("confirmation frame has unexpected length"))
}

/// Verifies a ServerConfirm frame against this party's derived session
/// keys. Failure (wrong pinned server key, a real man-in-the-middle, or
/// simple misconfiguration) must abort the connection immediately — there
/// is no fallback or retry.
pub fn verify_confirmation_frame(
    session_keys: &mut SessionKeys,
    frame: &[u8],
) -> anyhow::Result<()> {
    let plaintext = session_keys.recv.open(frame, CONFIRMATION_AAD)?;
    if !plaintext.is_empty() {
        return Err(anyhow::anyhow!(
            "confirmation frame carried unexpected payload"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn paired_session_keys() -> (SessionKeys, SessionKeys) {
        let server_secret = StaticSecret::from([7u8; 32]);
        let client_secret = StaticSecret::from([9u8; 32]);
        let server_public = PublicKey::from(&server_secret);
        let client_public = PublicKey::from(&client_secret);

        let server_shared = server_secret.diffie_hellman(&client_public);
        let client_shared = client_secret.diffie_hellman(&server_public);

        (
            SessionKeys::derive_for_server(&server_shared).unwrap(),
            SessionKeys::derive_for_client(&client_shared).unwrap(),
        )
    }

    #[test]
    fn seal_then_open_round_trips() {
        let (mut server, mut client) = paired_session_keys();

        let ciphertext = server.send.seal(b"hello from server", b"").unwrap();
        let plaintext = client.recv.open(&ciphertext, b"").unwrap();
        assert_eq!(plaintext, b"hello from server");

        let ciphertext = client.send.seal(b"hello from client", b"").unwrap();
        let plaintext = server.recv.open(&ciphertext, b"").unwrap();
        assert_eq!(plaintext, b"hello from client");
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let (mut server, mut client) = paired_session_keys();

        let mut ciphertext = server.send.seal(b"hello", b"").unwrap();
        *ciphertext.last_mut().unwrap() ^= 0xff;

        assert!(client.recv.open(&ciphertext, b"").is_err());
    }

    #[test]
    fn open_rejects_a_replayed_earlier_frame() {
        let (mut server, mut client) = paired_session_keys();

        let first = server.send.seal(b"one", b"").unwrap();
        let _second = server.send.seal(b"two", b"").unwrap();

        // Opening `first` normally advances the receiver's counter to 1.
        let opened = client.recv.open(&first, b"").unwrap();
        assert_eq!(opened, b"one");

        // Replaying the same frame must now fail: the receiver's counter
        // has moved on to expect the nonce that sealed `second`, not the
        // one that sealed `first`.
        assert!(client.recv.open(&first, b"").is_err());
    }

    #[test]
    fn seal_errors_rather_than_panics_or_wraps_at_counter_overflow() {
        let (mut server, _client) = paired_session_keys();
        server.send.counter = u64::MAX;

        assert!(server.send.seal(b"one more", b"").is_err());
    }

    #[test]
    fn open_errors_rather_than_panics_or_wraps_at_counter_overflow() {
        let (_server, mut client) = paired_session_keys();
        client.recv.counter = u64::MAX;

        assert!(client.recv.open(&[0u8; 32], b"").is_err());
    }

    #[test]
    fn plaintext_variant_passes_bytes_through_unchanged() {
        let mut security = ConnectionSecurity::Plaintext;

        let sealed = security.seal(b"unchanged").unwrap();
        assert_eq!(sealed, b"unchanged");

        let opened = security.open(b"still unchanged").unwrap();
        assert_eq!(opened, b"still unchanged");
    }

    #[test]
    fn encrypted_variant_seals_and_opens_through_the_underlying_session_keys() {
        let (server_keys, client_keys) = paired_session_keys();
        let mut server_security = ConnectionSecurity::Encrypted(server_keys);
        let mut client_security = ConnectionSecurity::Encrypted(client_keys);

        let sealed = server_security.seal(b"through the enum").unwrap();
        assert_ne!(sealed, b"through the enum");

        let opened = client_security.open(&sealed).unwrap();
        assert_eq!(opened, b"through the enum");
    }

    #[test]
    fn confirmation_frame_is_exactly_sixteen_bytes_and_verifies_on_the_other_side() {
        let (mut server, mut client) = paired_session_keys();

        let frame = build_confirmation_frame(&mut server).unwrap();
        assert_eq!(frame.len(), CONFIRMATION_FRAME_LEN);

        assert!(verify_confirmation_frame(&mut client, &frame).is_ok());
    }

    #[test]
    fn confirmation_frame_from_a_different_shared_secret_fails_to_verify() {
        let (mut server, _client) = paired_session_keys();
        let frame = build_confirmation_frame(&mut server).unwrap();

        // A client that derived keys from a different (e.g. wrong pinned
        // server key) shared secret must not be able to verify this frame.
        let wrong_client_secret = StaticSecret::from([42u8; 32]);
        let wrong_server_public = PublicKey::from(&StaticSecret::from([1u8; 32]));
        let wrong_shared = wrong_client_secret.diffie_hellman(&wrong_server_public);
        let mut wrong_client = SessionKeys::derive_for_client(&wrong_shared).unwrap();

        assert!(verify_confirmation_frame(&mut wrong_client, &frame).is_err());
    }

    // The all-zero point is a validly-encoded Curve25519 public key that
    // forces the ECDH output to the identity element — a low-order-point
    // attack (see `SharedSecret::was_contributory`'s docs) a MITM could use
    // to make the shared secret a fixed, publicly-known value instead of
    // one only the two real parties could compute.
    fn non_contributory_shared_secret() -> SharedSecret {
        let secret = StaticSecret::from([5u8; 32]);
        let low_order_public = PublicKey::from([0u8; 32]);
        secret.diffie_hellman(&low_order_public)
    }

    #[test]
    fn derive_for_server_rejects_a_non_contributory_shared_secret() {
        let shared = non_contributory_shared_secret();
        assert!(SessionKeys::derive_for_server(&shared).is_err());
    }

    #[test]
    fn derive_for_client_rejects_a_non_contributory_shared_secret() {
        let shared = non_contributory_shared_secret();
        assert!(SessionKeys::derive_for_client(&shared).is_err());
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // Cross-language contract: client/test/handshake.test.js uses the exact
    // same fixed 32-byte scalars and asserts the exact same hex-encoded
    // confirmation frame. A mismatch here means the Rust and JS
    // implementations have drifted (wrong HKDF labels, wrong nonce
    // construction, wrong AEAD parameters, ...) and would fail to
    // interoperate. This deliberately only exercises the public handshake
    // API (build_confirmation_frame), not internal key material, so it
    // doubles as a check that the actual wire bytes match, not just some
    // intermediate value.
    //
    #[test]
    fn cross_language_test_vector() {
        let server_secret = StaticSecret::from([1u8; 32]);
        let client_secret = StaticSecret::from([2u8; 32]);
        let client_public = PublicKey::from(&client_secret);

        let shared = server_secret.diffie_hellman(&client_public);
        let mut server_keys = SessionKeys::derive_for_server(&shared).unwrap();
        let frame = build_confirmation_frame(&mut server_keys).unwrap();

        assert_eq!(to_hex(&frame), "3cefb8b6a2d28e0c1c96d8c5d7919cf9");
    }
}
