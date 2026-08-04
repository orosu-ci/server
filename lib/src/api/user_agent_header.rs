use crate::api::UserAgentHeader;
use axum::http::HeaderValue;

impl Default for UserAgentHeader {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

impl From<UserAgentHeader> for HeaderValue {
    fn from(value: UserAgentHeader) -> Self {
        format!("Orosu/{}", value.version).parse().unwrap()
    }
}

impl TryFrom<&HeaderValue> for UserAgentHeader {
    type Error = anyhow::Error;

    fn try_from(value: &HeaderValue) -> Result<Self, Self::Error> {
        let string = value.to_str()?;
        let parts: Vec<&str> = string.split('/').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid user agent header: {string}");
        }
        if parts[0] != "Orosu" {
            anyhow::bail!("Invalid user agent header: {string}");
        }
        Ok(Self {
            version: parts[1].to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_uses_the_crate_version() {
        let header = UserAgentHeader::default();
        assert_eq!(header.version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn header_value_conversion_formats_as_orosu_slash_version() {
        let header = UserAgentHeader {
            version: "1.2.3".to_string(),
        };
        let header_value: HeaderValue = header.into();
        assert_eq!(header_value.to_str().unwrap(), "Orosu/1.2.3");
    }

    #[test]
    fn valid_header_parses_the_version() {
        let header_value = HeaderValue::from_static("Orosu/1.2.3");
        let header = UserAgentHeader::try_from(&header_value).unwrap();
        assert_eq!(header.version, "1.2.3");
    }

    #[test]
    fn round_trips_through_header_value() {
        let original = UserAgentHeader {
            version: "9.9.9".to_string(),
        };
        let header_value: HeaderValue = original.into();
        let parsed = UserAgentHeader::try_from(&header_value).unwrap();
        assert_eq!(parsed.version, "9.9.9");
    }

    #[test]
    fn rejects_a_header_with_no_slash() {
        let header_value = HeaderValue::from_static("Orosu");
        assert!(UserAgentHeader::try_from(&header_value).is_err());
    }

    #[test]
    fn rejects_a_header_with_the_wrong_product_name() {
        let header_value = HeaderValue::from_static("curl/8.0.0");
        assert!(UserAgentHeader::try_from(&header_value).is_err());
    }

    #[test]
    fn rejects_a_header_with_more_than_one_slash() {
        // Documents the exact (slightly surprising) behavior: it requires
        // EXACTLY two `/`-separated parts, so a version string containing
        // its own slash would be rejected outright rather than the version
        // being taken as everything after the first slash.
        let header_value = HeaderValue::from_static("Orosu/1.2.3/extra");
        assert!(UserAgentHeader::try_from(&header_value).is_err());
    }

    #[test]
    fn rejects_a_header_that_is_not_valid_ascii() {
        let header_value = HeaderValue::from_bytes(b"Orosu/\xff\xfe").unwrap();
        assert!(UserAgentHeader::try_from(&header_value).is_err());
    }
}
