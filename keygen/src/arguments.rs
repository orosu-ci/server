use std::path::PathBuf;

#[derive(Debug, clap::Parser)]
#[command(version, about, long_about = None)]
pub struct CliArguments {
    #[clap(short, long)]
    pub name: Option<String>,
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
}
