use std::path::PathBuf;

#[derive(Debug, Clone, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum KeyKind {
    /// A client identity key (Ed25519, signs the JWT used to authenticate
    /// to orosu-server) — what this tool has always generated.
    #[default]
    Client,
    /// A server encryption identity key (X25519, used for the protocol v2
    /// end-to-end encryption handshake — see api/handshake.rs). One per
    /// orosu-server instance, not per client.
    Server,
}

#[derive(Debug, clap::Parser)]
#[command(version, about, long_about = None)]
pub struct CliArguments {
    #[clap(short, long)]
    pub name: Option<String>,
    #[clap(long, value_enum, default_value_t = KeyKind::Client)]
    pub kind: KeyKind,
    #[clap(long)]
    pub private_key_output: Option<PathBuf>,
    #[clap(long)]
    pub public_key_output: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn all_fields_are_optional() {
        let args = CliArguments::try_parse_from(["orosu-keygen"]).unwrap();
        assert!(args.name.is_none());
        assert!(args.private_key_output.is_none());
        assert!(args.public_key_output.is_none());
    }

    #[test]
    fn parses_all_long_flags() {
        let args = CliArguments::try_parse_from([
            "orosu-keygen",
            "--name",
            "my-client",
            "--private-key-output",
            "priv.key",
            "--public-key-output",
            "pub.key",
        ])
        .unwrap();
        assert_eq!(args.name, Some("my-client".to_string()));
        assert_eq!(args.private_key_output, Some(PathBuf::from("priv.key")));
        assert_eq!(args.public_key_output, Some(PathBuf::from("pub.key")));
    }

    #[test]
    fn name_has_a_short_flag() {
        let args = CliArguments::try_parse_from(["orosu-keygen", "-n", "shorthand"]).unwrap();
        assert_eq!(args.name, Some("shorthand".to_string()));
    }

    // Bare `orosu-keygen` must remain a behaviorally unchanged client-key
    // generator — this is the backward-compatibility guarantee for the
    // --kind flag itself.
    #[test]
    fn kind_defaults_to_client() {
        let args = CliArguments::try_parse_from(["orosu-keygen"]).unwrap();
        assert_eq!(args.kind, KeyKind::Client);
    }

    #[test]
    fn kind_accepts_server() {
        let args = CliArguments::try_parse_from(["orosu-keygen", "--kind", "server"]).unwrap();
        assert_eq!(args.kind, KeyKind::Server);
    }

    #[test]
    fn kind_rejects_an_unrecognized_value() {
        let result = CliArguments::try_parse_from(["orosu-keygen", "--kind", "nonsense"]);
        assert!(result.is_err());
    }
}
