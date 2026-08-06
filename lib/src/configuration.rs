use crate::client::Client;
use anyhow::Context;
use cidr::IpCidr;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub enum ListenConfiguration {
    #[serde(rename = "tcp")]
    Tcp(SocketAddr),
    #[cfg(unix)]
    #[serde(rename = "socket")]
    Socket(PathBuf),
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Default, Clone, clap::ValueEnum)]
pub enum LogLevelConfiguration {
    #[serde(rename = "debug")]
    Debug,
    #[serde(rename = "info")]
    #[default]
    Info,
    #[serde(rename = "warn")]
    Warn,
    #[serde(rename = "error")]
    Error,
}

impl From<LogLevelConfiguration> for tracing::Level {
    fn from(value: LogLevelConfiguration) -> Self {
        match value {
            LogLevelConfiguration::Debug => tracing::Level::DEBUG,
            LogLevelConfiguration::Info => tracing::Level::INFO,
            LogLevelConfiguration::Warn => tracing::Level::WARN,
            LogLevelConfiguration::Error => tracing::Level::ERROR,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Configuration {
    #[serde(rename = "listen")]
    pub listen: ListenConfiguration,
    #[serde(rename = "log_level", default)]
    pub log_level: LogLevelConfiguration,
    #[serde(rename = "whitelisted_ips")]
    pub ip_whitelist: Option<Vec<IpCidr>>,
    #[serde(rename = "blacklisted_ips")]
    pub ip_blacklist: Option<Vec<IpCidr>>,
    #[serde(rename = "clients")]
    pub clients: Vec<Client>,
    /// Path to the server's own static X25519 private key (see
    /// cryptography::ServerStaticKey), generated with
    /// `orosu-keygen --kind server`. Optional and absent by default: this
    /// server only ever accepts protocol version 2 (the end-to-end
    /// encryption handshake) once this is configured — see
    /// api::protocol_version::supported_protocol_versions.
    #[serde(rename = "encryption_key_file", default)]
    pub encryption_key_file: Option<PathBuf>,
}

impl Configuration {
    pub fn from_file(path: &PathBuf) -> anyhow::Result<Self> {
        let file = std::fs::File::open(path)
            .with_context(|| format!("Failed to open configuration file at {}", path.display()))?;
        let reader = std::io::BufReader::new(file);
        let configuration: Self =
            serde_saphyr::from_reader(reader).with_context(|| "Failed to parse configuration")?;
        configuration.validate()?;
        Ok(configuration)
    }

    /// Rejects a config where two clients share a `name`, or where one
    /// client's own scripts share a `name` with each other. Both
    /// `auth_scope.rs`'s client lookup and `handler/tasks.rs`'s script
    /// lookup use `.find()`, which silently resolves to the first match —
    /// without this, a duplicate name would make the second entry
    /// permanently unreachable with no warning at startup, looking like a
    /// working config. The same script name under two *different* clients
    /// is fine, since scripts are only ever looked up already scoped to one
    /// authenticated client.
    fn validate(&self) -> anyhow::Result<()> {
        let mut seen_clients = std::collections::HashSet::new();
        for client in &self.clients {
            if !seen_clients.insert(client.name.as_str()) {
                anyhow::bail!(
                    "Duplicate client name in configuration: \"{}\"",
                    client.name
                );
            }
            let mut seen_scripts = std::collections::HashSet::new();
            for script in &client.scripts {
                if !seen_scripts.insert(script.name.as_str()) {
                    anyhow::bail!(
                        "Duplicate script name \"{}\" for client \"{}\"",
                        script.name,
                        client.name
                    );
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::configuration::ListenConfiguration::{Socket, Tcp};
    use crate::configuration::{Configuration, ListenConfiguration, LogLevelConfiguration};
    use cidr::IpCidr;
    use std::net::IpAddr;
    use std::path::PathBuf;

    #[test]
    fn listen_configuration_tcp_ipv4_deserialization() {
        let yaml = r#"tcp: "0.0.0.0:8081""#;
        let configuration: ListenConfiguration = serde_saphyr::from_str(yaml).unwrap();

        let Tcp(addr) = configuration else {
            panic!("Expected Tcp configuration");
        };
        assert_eq!(addr.ip(), IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));
        assert_eq!(addr.port(), 8081);
    }

    #[test]
    fn listen_configuration_tcp_ipv6_deserialization() {
        let yaml = r#"tcp: "[fc00:db20:35b:7399::5]:8081""#;
        let configuration: ListenConfiguration = serde_saphyr::from_str(yaml).unwrap();

        let Tcp(addr) = configuration else {
            panic!("Expected Tcp configuration");
        };
        assert_eq!(
            addr.ip(),
            IpAddr::V6(std::net::Ipv6Addr::new(
                0xfc00, 0xdb20, 0x35b, 0x7399, 0, 0, 0, 0x5
            ))
        );
        assert_eq!(addr.port(), 8081);
    }

    #[test]
    #[should_panic(expected = "invalid socket address syntax")]
    fn listen_configuration_tcp_malformed_deserialization() {
        let yaml = r#"tcp: "test:01""#;
        let _: ListenConfiguration = serde_saphyr::from_str(yaml).unwrap();
    }

    #[test]
    fn listen_configuration_socket_deserialization() {
        let yaml = r#"socket: "/tmp/socket""#;
        let configuration: ListenConfiguration = serde_saphyr::from_str(yaml).unwrap();
        let Socket(path) = configuration else {
            panic!("Expected Socket configuration");
        };
        assert_eq!(path, PathBuf::from("/tmp/socket"));
    }

    #[test]
    fn read_full_config() {
        let contents = r#"
listen:
  tcp: "0.0.0.0:8081"
log_level: error
whitelisted_ips:
  - "127.0.0.1"
blacklisted_ips:
  - "192.168.0.1"
  - "1.1.1.0/24"
clients:
  - name: "my-client"
    secret_file: "public.key"
    whitelisted_ips:
      - "127.0.0.1"
    blacklisted_ips:
      - "192.168.0.1"
    scripts:
      - name: "my-script"
        command:
          - "echo"
          - "Hello from Orosu"
"#;
        let configuration: Configuration = serde_saphyr::from_str(contents).unwrap();
        let Tcp(addr) = configuration.listen else {
            panic!("Expected Tcp configuration");
        };
        assert_eq!(addr.ip(), IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));
        assert_eq!(addr.port(), 8081);
        assert_eq!(configuration.log_level, LogLevelConfiguration::Error);
        assert_eq!(configuration.clients.len(), 1);
        assert_eq!(configuration.clients[0].name, "my-client");
        assert_eq!(configuration.clients[0].scripts.len(), 1);
        assert_eq!(configuration.clients[0].scripts[0].name, "my-script");
        assert_eq!(configuration.clients[0].scripts[0].command[0], "echo");
        assert_eq!(
            configuration.clients[0].secret_file,
            PathBuf::from("public.key")
        );
        assert_eq!(
            configuration.clients[0].whitelisted_ips,
            Some(vec![
                IpCidr::new(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 32).unwrap()
            ])
        );
        assert_eq!(
            configuration.clients[0].blacklisted_ips,
            Some(vec![
                IpCidr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 1)), 32).unwrap()
            ])
        );
        assert_eq!(
            configuration.ip_whitelist,
            Some(vec![
                IpCidr::new(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 32).unwrap()
            ])
        );
        assert_eq!(
            configuration.ip_blacklist,
            Some(vec![
                IpCidr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 1)), 32).unwrap(),
                IpCidr::new(IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 0)), 24).unwrap()
            ])
        );
    }

    #[test]
    fn encryption_key_file_parses_when_present() {
        let contents = r#"
listen:
  tcp: "0.0.0.0:8081"
encryption_key_file: "secrets/server.key"
clients: []
"#;
        let configuration: Configuration = serde_saphyr::from_str(contents).unwrap();
        assert_eq!(
            configuration.encryption_key_file,
            Some(PathBuf::from("secrets/server.key"))
        );
    }

    // This is the config-side half of the backward-compatibility story: an
    // orosu-server upgrade with an existing config.yaml that predates this
    // field must parse it as absent, not fail or silently enable
    // encryption.
    #[test]
    fn encryption_key_file_defaults_to_none_when_absent() {
        let contents = r#"
listen:
  tcp: "0.0.0.0:8081"
clients: []
"#;
        let configuration: Configuration = serde_saphyr::from_str(contents).unwrap();
        assert_eq!(configuration.encryption_key_file, None);
    }

    #[test]
    fn log_level_defaults_to_info() {
        assert_eq!(
            LogLevelConfiguration::default(),
            LogLevelConfiguration::Info
        );
    }

    #[test]
    fn log_level_omitted_from_yaml_defaults_to_info() {
        let contents = r#"
listen:
  tcp: "0.0.0.0:8081"
clients: []
"#;
        let configuration: Configuration = serde_saphyr::from_str(contents).unwrap();
        assert_eq!(configuration.log_level, LogLevelConfiguration::Info);
    }

    #[test]
    fn log_level_converts_to_the_matching_tracing_level() {
        assert_eq!(
            tracing::Level::from(LogLevelConfiguration::Debug),
            tracing::Level::DEBUG
        );
        assert_eq!(
            tracing::Level::from(LogLevelConfiguration::Info),
            tracing::Level::INFO
        );
        assert_eq!(
            tracing::Level::from(LogLevelConfiguration::Warn),
            tracing::Level::WARN
        );
        assert_eq!(
            tracing::Level::from(LogLevelConfiguration::Error),
            tracing::Level::ERROR
        );
    }

    #[test]
    fn from_file_reads_and_parses_a_real_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(
            &path,
            r#"
listen:
  tcp: "127.0.0.1:9000"
clients: []
"#,
        )
        .unwrap();

        let configuration = Configuration::from_file(&path).unwrap();
        let Tcp(addr) = configuration.listen else {
            panic!("Expected Tcp configuration");
        };
        assert_eq!(addr.port(), 9000);
    }

    #[test]
    fn from_file_errors_cleanly_on_a_missing_file() {
        let path = PathBuf::from("/nonexistent/path/to/config.yaml");
        let result = Configuration::from_file(&path);
        assert!(result.is_err());
    }

    #[test]
    fn from_file_errors_cleanly_on_malformed_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, "not: [valid, config").unwrap();

        let result = Configuration::from_file(&path);
        assert!(result.is_err());
    }

    // auth_scope.rs's client lookup and handler/tasks.rs's script lookup
    // both use `.find()`, which silently resolves to the first match — a
    // duplicate name would otherwise make the second entry permanently
    // unreachable with no warning at startup, looking like a working
    // config to an operator who copy-pasted a client block and forgot to
    // rename it.
    #[test]
    fn from_file_rejects_a_config_with_duplicate_client_names() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(
            &path,
            r#"
listen:
  tcp: "127.0.0.1:9000"
clients:
  - name: "same-name"
    secret_file: "a.key"
    scripts: []
  - name: "same-name"
    secret_file: "b.key"
    scripts: []
"#,
        )
        .unwrap();

        let result = Configuration::from_file(&path);
        assert!(result.is_err());
    }

    #[test]
    fn from_file_rejects_a_config_with_duplicate_script_names_for_the_same_client() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(
            &path,
            r#"
listen:
  tcp: "127.0.0.1:9000"
clients:
  - name: "test-client"
    secret_file: "a.key"
    scripts:
      - name: "same-name"
        command: ["echo", "one"]
      - name: "same-name"
        command: ["echo", "two"]
"#,
        )
        .unwrap();

        let result = Configuration::from_file(&path);
        assert!(result.is_err());
    }

    // The same script name under two *different* clients is fine — scripts
    // are only looked up scoped to the already-authenticated client, so
    // there's no ambiguity for `.find()` to silently resolve wrong here.
    #[test]
    fn from_file_allows_the_same_script_name_across_different_clients() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(
            &path,
            r#"
listen:
  tcp: "127.0.0.1:9000"
clients:
  - name: "client-a"
    secret_file: "a.key"
    scripts:
      - name: "deploy"
        command: ["echo", "a"]
  - name: "client-b"
    secret_file: "b.key"
    scripts:
      - name: "deploy"
        command: ["echo", "b"]
"#,
        )
        .unwrap();

        assert!(Configuration::from_file(&path).is_ok());
    }
}
