use crate::api::ProtocolVersionHeader;
use axum::http::HeaderValue;

/// The current wire-protocol version. Bump this whenever the
/// envelope/handshake contract changes in a way that breaks compatibility
/// with a client built against the previous value — and add the new value
/// to `supported_protocol_versions` below so the server can keep accepting
/// the version it's replacing.
///
/// Version 0 is implicit, not a value anything ever sends on purpose: every
/// client built before this header existed sends no
/// `Orosu-Protocol-Version` header at all. The server treats that absence
/// as version 0 rather than a malformed request — see auth_scope.rs.
pub const PROTOCOL_VERSION: u32 = 1;

/// Protocol version 2: adds the end-to-end encryption handshake (see
/// api/handshake.rs) underneath the existing envelope layer. A client
/// speaking this version performs the handshake before sending
/// `StartTaskRequest`; a client speaking 0 or 1 behaves exactly as before.
pub const PROTOCOL_VERSION_ENCRYPTED_V2: u32 = 2;

/// Every protocol version this server will currently accept a client
/// speaking. Version 0 has to stay listed until every currently-deployed
/// client (including, as of introducing the version header, every
/// already-published `orosu-client` binary — a Rust CLI since discontinued
/// in favor of the JS action — and every JS action release that predates
/// that header) has actually been upgraded; dropping it here would reject
/// that live traffic outright rather than let it interoperate during the
/// rollout. See server/auth_scope.rs for the check that uses this.
///
/// Deliberately a function, not a const: whether version 2 is accepted
/// depends on whether this server instance has an encryption key configured
/// (`Configuration.encryption_key_file`). This is the entire backward
/// compatibility story for the encryption feature — an orosu-server binary
/// upgrade with an existing, unmodified config.yaml calls this with `false`
/// and gets today's exact `[0, 1]`, so nothing changes for a deployment
/// that hasn't opted in.
pub fn supported_protocol_versions(encryption_configured: bool) -> Vec<u32> {
    if encryption_configured {
        vec![0, PROTOCOL_VERSION, PROTOCOL_VERSION_ENCRYPTED_V2]
    } else {
        vec![0, PROTOCOL_VERSION]
    }
}

/// Shared by both the sending (api/client.rs) and receiving
/// (server/auth_scope.rs) sides, so they can't drift on the literal string.
pub const PROTOCOL_VERSION_HEADER_NAME: &str = "orosu-protocol-version";

impl Default for ProtocolVersionHeader {
    fn default() -> Self {
        Self {
            version: PROTOCOL_VERSION,
        }
    }
}

impl From<ProtocolVersionHeader> for HeaderValue {
    fn from(value: ProtocolVersionHeader) -> Self {
        value.version.to_string().parse().unwrap()
    }
}

impl TryFrom<&HeaderValue> for ProtocolVersionHeader {
    type Error = anyhow::Error;

    fn try_from(value: &HeaderValue) -> Result<Self, Self::Error> {
        let string = value.to_str()?;
        let version: u32 = string
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid protocol version header: {string}"))?;
        Ok(Self { version })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_uses_the_crate_protocol_version() {
        let header = ProtocolVersionHeader::default();
        assert_eq!(header.version, PROTOCOL_VERSION);
    }

    #[test]
    fn supported_protocol_versions_without_encryption_matches_todays_set_exactly() {
        // Backward compatibility on the server binary: an orosu-server
        // upgrade with no encryption_key_file configured must not change
        // what versions it accepts at all.
        assert_eq!(
            supported_protocol_versions(false),
            vec![0, PROTOCOL_VERSION]
        );
    }

    #[test]
    fn supported_protocol_versions_with_encryption_additionally_includes_the_encrypted_version() {
        let versions = supported_protocol_versions(true);
        assert!(versions.contains(&0));
        assert!(versions.contains(&PROTOCOL_VERSION));
        assert!(versions.contains(&PROTOCOL_VERSION_ENCRYPTED_V2));
    }

    #[test]
    fn header_value_conversion_formats_as_a_bare_integer() {
        let header = ProtocolVersionHeader { version: 7 };
        let header_value: HeaderValue = header.into();
        assert_eq!(header_value.to_str().unwrap(), "7");
    }

    #[test]
    fn valid_header_parses_the_version() {
        let header_value = HeaderValue::from_static("3");
        let header = ProtocolVersionHeader::try_from(&header_value).unwrap();
        assert_eq!(header.version, 3);
    }

    #[test]
    fn round_trips_through_header_value() {
        let original = ProtocolVersionHeader { version: 42 };
        let header_value: HeaderValue = original.into();
        let parsed = ProtocolVersionHeader::try_from(&header_value).unwrap();
        assert_eq!(parsed.version, 42);
    }

    #[test]
    fn rejects_a_non_numeric_value() {
        let header_value = HeaderValue::from_static("not-a-number");
        assert!(ProtocolVersionHeader::try_from(&header_value).is_err());
    }

    #[test]
    fn rejects_a_negative_number() {
        let header_value = HeaderValue::from_static("-1");
        assert!(ProtocolVersionHeader::try_from(&header_value).is_err());
    }

    #[test]
    fn rejects_a_decimal_value() {
        let header_value = HeaderValue::from_static("1.5");
        assert!(ProtocolVersionHeader::try_from(&header_value).is_err());
    }

    #[test]
    fn rejects_a_value_that_is_not_valid_ascii() {
        let header_value = HeaderValue::from_bytes(b"\xff\xfe").unwrap();
        assert!(ProtocolVersionHeader::try_from(&header_value).is_err());
    }
}
