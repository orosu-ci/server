use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::SigningKey;
use ed25519_dalek::ed25519::signature::rand_core::OsRng;

#[derive(
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
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
}
