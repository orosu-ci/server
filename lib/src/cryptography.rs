use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::SigningKey;
use ed25519_dalek::ed25519::signature::rand_core::OsRng;

// Deliberately no `Debug` derive — `key` is the raw Ed25519 signing seed.
// Every other secret-holding type in this file (`ServerKeygen`,
// `ServerStaticKey`) omits it the same way, so a future
// `tracing::debug!("{:?}", key)` fails to compile instead of leaking a
// private key into logs.
#[derive(
    Clone, serde::Serialize, serde::Deserialize, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct ClientKey {
    pub client_name: String,
    pub key: Vec<u8>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Claims {
    pub(crate) sub: String,
    pub(crate) exp: usize,
}

impl ClientKey {
    /// JSON is the current key format (see `client_key_wire_format_is_plain_base64_json`
    /// below) and what `Keygen::private_key_base64` writes for any key generated
    /// today. But keys generated before that migration were written with rkyv, a
    /// binary format, and holders of those keys shouldn't be forced to re-run
    /// `orosu-keygen` just to keep working — so a value that isn't valid JSON is
    /// retried as rkyv before giving up. New keys are never written as rkyv; this
    /// is a read-only compatibility path, not a second write format.
    pub fn from_string(value: String) -> anyhow::Result<Self> {
        let bytes = STANDARD.decode(value).context("invalid key format")?;
        if let Ok(key) = serde_json::from_slice::<Self>(&bytes) {
            return Ok(key);
        }
        rkyv::from_bytes::<Self, rkyv::rancor::Error>(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid key format"))
    }
}

pub struct Keygen {
    public_key: Vec<u8>,
    private_key: ClientKey,
}

impl Keygen {
    pub fn new(name: String) -> Self {
        let key = SigningKey::generate(&mut OsRng);

        let private_key = key.to_bytes();
        let public_key = key.verifying_key().to_bytes().into();

        let private_key = ClientKey {
            client_name: name,
            key: private_key.into(),
        };

        Self {
            public_key,
            private_key,
        }
    }

    pub fn public_key(&self) -> &Vec<u8> {
        &self.public_key
    }

    pub fn private_key(&self) -> &ClientKey {
        &self.private_key
    }

    pub fn public_key_base64(&self) -> String {
        STANDARD.encode(&self.public_key)
    }

    pub fn private_key_base64(&self) -> String {
        let private_key = serde_json::to_vec(&self.private_key).unwrap();
        STANDARD.encode(private_key)
    }
}

/// Generates the server's own static X25519 identity key, used to
/// authenticate `orosu-server` to clients during the protocol-v2
/// encryption handshake (see api/handshake.rs). Unlike `Keygen`'s
/// `ClientKey`, there's no name to attach — this is one identity per
/// server, not per client — so both halves are plain base64 of the raw 32
/// bytes, matching how `Client.secret_file` is already read in
/// server/auth_scope.rs, rather than the JSON-wrapped `ClientKey` shape.
pub struct ServerKeygen {
    public_key: [u8; 32],
    private_key: [u8; 32],
}

impl ServerKeygen {
    pub fn new() -> Self {
        let secret = x25519_dalek::StaticSecret::random();
        let public_key = x25519_dalek::PublicKey::from(&secret);
        Self {
            public_key: public_key.to_bytes(),
            private_key: secret.to_bytes(),
        }
    }

    pub fn public_key_base64(&self) -> String {
        STANDARD.encode(self.public_key)
    }

    pub fn private_key_base64(&self) -> String {
        STANDARD.encode(self.private_key)
    }
}

impl Default for ServerKeygen {
    fn default() -> Self {
        Self::new()
    }
}

/// The server's own static X25519 private key, loaded from
/// `Configuration.encryption_key_file`. Unlike `Client.secret_file` (a
/// client's public key, re-read from disk on every auth attempt so
/// revocation takes effect without a restart), this is loaded once at
/// startup: rotating the server's own identity inherently requires a
/// restart and coordinated re-pinning on every client anyway, so
/// per-connection re-reading would add overhead with no matching benefit.
pub struct ServerStaticKey(x25519_dalek::StaticSecret);

impl ServerStaticKey {
    pub fn from_base64(value: &str) -> anyhow::Result<Self> {
        let bytes = STANDARD
            .decode(value.trim())
            .context("invalid server encryption key: not valid base64")?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid server encryption key: expected 32 bytes"))?;
        Ok(Self(x25519_dalek::StaticSecret::from(bytes)))
    }

    pub fn from_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read encryption key file {}", path.display()))?;
        Self::from_base64(&contents)
    }

    pub(crate) fn as_static_secret(&self) -> &x25519_dalek::StaticSecret {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, Verifier, VerifyingKey};

    #[test]
    fn private_key_base64_roundtrips_through_client_key_from_string() {
        let keygen = Keygen::new("roundtrip-client".to_string());

        let parsed = ClientKey::from_string(keygen.private_key_base64()).unwrap();

        assert_eq!(parsed.client_name, "roundtrip-client");
        assert_eq!(parsed.key, keygen.private_key().key);
    }

    // Locks in the format newly generated keys are written in, and that the
    // JS action (client/src/auth.js) depends on: base64(JSON({"client_name":
    // string, "key": [u8; 32]})). `from_string` also reads the older rkyv
    // format (see `reads_a_key_written_in_the_old_rkyv_format` below), but
    // that's a read-only compatibility path — Keygen must never start
    // writing rkyv again.
    #[test]
    fn client_key_wire_format_is_plain_base64_json() {
        let keygen = Keygen::new("wire-format-client".to_string());

        let decoded = STANDARD.decode(keygen.private_key_base64()).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&decoded).unwrap();

        assert_eq!(json["client_name"], "wire-format-client");
        let key = json["key"].as_array().expect("key should be a JSON array");
        assert_eq!(key.len(), 32);
        assert!(key.iter().all(|b| b.is_u64() && b.as_u64().unwrap() <= 255));
    }

    #[test]
    fn from_string_rejects_invalid_base64() {
        let result = ClientKey::from_string("not valid base64 !!!".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn from_string_rejects_valid_base64_that_is_not_the_expected_json_shape() {
        let garbage = STANDARD.encode(b"{\"unexpected\":\"shape\"}");
        let result = ClientKey::from_string(garbage);
        assert!(result.is_err());
    }

    // Keys generated before the JSON migration were written with rkyv, a
    // binary format — holders of those keys shouldn't be forced to re-run
    // orosu-keygen just to keep working. This locks in that from_string
    // still reads that old format even though Keygen never writes it again.
    #[test]
    fn reads_a_key_written_in_the_old_rkyv_format() {
        let private_key = ClientKey {
            client_name: "old-format-client".to_string(),
            key: vec![1u8; 32],
        };
        let encoded = rkyv::to_bytes::<rkyv::rancor::Error>(&private_key).unwrap();
        let base64 = STANDARD.encode(encoded);

        let parsed = ClientKey::from_string(base64).unwrap();

        assert_eq!(parsed.client_name, "old-format-client");
        assert_eq!(parsed.key, vec![1u8; 32]);
    }

    #[test]
    fn from_string_rejects_garbage_that_is_neither_json_nor_rkyv() {
        let garbage = STANDARD.encode(b"\x00\x01\x02not a valid encoding at all\xff\xfe");
        let result = ClientKey::from_string(garbage);
        assert!(result.is_err());
    }

    // Confirms the raw 32-byte seed and derived public key Keygen produces
    // are a genuine Ed25519 keypair — this is the exact relationship the JS
    // action's hand-rolled JWT signing (client/src/auth.js) depends on:
    // wrapping the seed in a fixed PKCS8 prefix and signing with it must
    // verify against the public key shipped separately to the server.
    #[test]
    fn keygen_produces_a_valid_ed25519_keypair() {
        let keygen = Keygen::new("signing-client".to_string());

        let seed: [u8; 32] = keygen.private_key().key.clone().try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&seed);

        let public_key_bytes: [u8; 32] = keygen.public_key().clone().try_into().unwrap();
        let verifying_key = VerifyingKey::from_bytes(&public_key_bytes).unwrap();
        assert_eq!(signing_key.verifying_key(), verifying_key);

        let message: &[u8] = b"test message";
        let signature = signing_key.sign(message);
        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    // Confirms ServerKeygen produces a genuine X25519 keypair: a peer using
    // the public key must derive the same shared secret as the server does
    // using the corresponding private key.
    #[test]
    fn server_keygen_produces_a_valid_x25519_keypair() {
        let server = ServerKeygen::new();
        let server_static_key = ServerStaticKey::from_base64(&server.private_key_base64()).unwrap();

        let peer_secret = x25519_dalek::StaticSecret::random();
        let peer_public = x25519_dalek::PublicKey::from(&peer_secret);

        let peer_public_bytes = STANDARD.decode(server.public_key_base64()).unwrap();
        let server_public: x25519_dalek::PublicKey =
            <[u8; 32]>::try_from(peer_public_bytes.as_slice())
                .unwrap()
                .into();

        let from_peer = peer_secret.diffie_hellman(&server_public);
        let from_server = server_static_key
            .as_static_secret()
            .diffie_hellman(&peer_public);
        assert_eq!(from_peer.as_bytes(), from_server.as_bytes());
    }

    // Unlike ClientKey, a server encryption key has no client_name — it's
    // plain base64 of the raw 32 bytes, matching how Client.secret_file is
    // already read in server/auth_scope.rs.
    #[test]
    fn server_keygen_keys_are_plain_base64_of_32_raw_bytes_not_json() {
        let server = ServerKeygen::new();

        let public_bytes = STANDARD.decode(server.public_key_base64()).unwrap();
        assert_eq!(public_bytes.len(), 32);

        let private_bytes = STANDARD.decode(server.private_key_base64()).unwrap();
        assert_eq!(private_bytes.len(), 32);
    }

    #[test]
    fn server_static_key_from_base64_roundtrips_with_server_keygen_output() {
        let server = ServerKeygen::new();
        let key = ServerStaticKey::from_base64(&server.private_key_base64()).unwrap();

        let public_bytes = STANDARD.decode(server.public_key_base64()).unwrap();
        let expected_public: x25519_dalek::PublicKey =
            <[u8; 32]>::try_from(public_bytes.as_slice())
                .unwrap()
                .into();

        let derived_public = x25519_dalek::PublicKey::from(key.as_static_secret());
        assert_eq!(derived_public.as_bytes(), expected_public.as_bytes());
    }

    #[test]
    fn server_static_key_from_base64_rejects_invalid_base64() {
        assert!(ServerStaticKey::from_base64("not valid base64 !!!").is_err());
    }

    #[test]
    fn server_static_key_from_base64_rejects_wrong_length() {
        let too_short = STANDARD.encode([1u8; 16]);
        assert!(ServerStaticKey::from_base64(&too_short).is_err());
    }

    #[test]
    fn server_static_key_from_file_reads_and_trims_whitespace() {
        let server = ServerKeygen::new();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.key");
        std::fs::write(&path, format!("{}\n", server.private_key_base64())).unwrap();

        let key = ServerStaticKey::from_file(&path).unwrap();
        let derived_public = x25519_dalek::PublicKey::from(key.as_static_secret());

        let public_bytes = STANDARD.decode(server.public_key_base64()).unwrap();
        assert_eq!(
            derived_public.as_bytes().as_slice(),
            public_bytes.as_slice()
        );
    }

    #[test]
    fn server_static_key_from_file_errors_on_missing_file() {
        let result = ServerStaticKey::from_file(std::path::Path::new("/nonexistent/server.key"));
        assert!(result.is_err());
    }
}
