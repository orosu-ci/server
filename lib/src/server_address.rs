use anyhow::Context;
use axum::http::Uri;
use std::ops::Deref;

pub struct ServerAddress(Uri);

impl ServerAddress {
    pub fn from_string(address: String) -> anyhow::Result<Self> {
        let mut parts = Uri::try_from(&address)
            .context("invalid server address format")?
            .into_parts();
        if parts.scheme.is_none() {
            parts.scheme = Some("wss".try_into()?);
        }
        if parts.path_and_query.is_none() {
            parts.path_and_query = Some("/".try_into()?);
        }
        let uri = Uri::from_parts(parts)?;
        Ok(ServerAddress(uri))
    }
}

impl Deref for ServerAddress {
    type Target = Uri;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_host_defaults_to_wss_scheme_and_root_path() {
        let address = ServerAddress::from_string("example.com".to_string()).unwrap();
        assert_eq!(address.scheme_str(), Some("wss"));
        assert_eq!(address.host(), Some("example.com"));
        assert_eq!(address.path(), "/");
    }

    #[test]
    fn host_with_port_and_no_scheme_defaults_to_wss() {
        let address = ServerAddress::from_string("example.com:8081".to_string()).unwrap();
        assert_eq!(address.scheme_str(), Some("wss"));
        assert_eq!(address.host(), Some("example.com"));
        assert_eq!(address.port_u16(), Some(8081));
        assert_eq!(address.path(), "/");
    }

    #[test]
    fn explicit_scheme_is_preserved() {
        let address = ServerAddress::from_string("ws://127.0.0.1:8091".to_string()).unwrap();
        assert_eq!(address.scheme_str(), Some("ws"));
        assert_eq!(address.host(), Some("127.0.0.1"));
        assert_eq!(address.port_u16(), Some(8091));
    }

    #[test]
    fn explicit_path_is_preserved_when_a_scheme_is_present() {
        let address = ServerAddress::from_string("wss://host:443/deploy/".to_string()).unwrap();
        assert_eq!(address.path(), "/deploy/");
    }

    // Documents real, verified behavior (not necessarily ideal): `Uri::try_from`
    // rejects a schemeless "host:port/path" outright, before this function's
    // own scheme-defaulting logic ever runs — so this specific combination
    // (no scheme, but a port AND a path) errors instead of defaulting to wss,
    // unlike a bare host or bare host:port on their own.
    #[test]
    fn schemeless_host_port_and_path_together_is_rejected() {
        let result = ServerAddress::from_string("host:443/deploy/".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn invalid_address_format_is_rejected() {
        let result = ServerAddress::from_string("not a valid uri".to_string());
        assert!(result.is_err());
    }
}
