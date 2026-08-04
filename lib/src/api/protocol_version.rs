use crate::api::ProtocolVersionHeader;
use axum::http::HeaderValue;

/// The wire-protocol version this crate speaks. Bump this whenever the
/// envelope/handshake contract changes in a way that breaks compatibility
/// with a client or server built against the previous value — see
/// server/auth_scope.rs's exact-match check, which rejects anything else.
///
/// Version 0 is implicit, not a value anything ever sends on purpose: every
/// client built before this header existed (which is every currently
/// released `orosu-client` and JS action, as of introducing this) sends no
/// `Orosu-Protocol-Version` header at all. The server treats that absence
/// as version 0 rather than a malformed request — see auth_scope.rs.
pub const PROTOCOL_VERSION: u32 = 1;

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
