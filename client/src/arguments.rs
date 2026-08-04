use orosu::configuration::LogLevelConfiguration;

#[derive(Debug, clap::Parser)]
#[command(version, about, long_about = None)]
pub struct CliArguments {
    pub variables: Vec<String>,
    #[clap(short, long)]
    pub address: String,
    #[clap(short, long)]
    pub script: String,
    #[clap(short, long)]
    pub key: String,
    #[clap(short, long)]
    pub retries: Option<u8>,
    #[clap(short, long, default_value = "info")]
    pub log_level: LogLevelConfiguration,
    #[clap(short, long)]
    pub file: Option<Vec<String>>,
    #[clap(short, long, default_value_t = 65536)]
    pub chunk_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_required_flags_and_positional_variables() {
        let args = CliArguments::try_parse_from([
            "orosu-client",
            "--address",
            "wss://host",
            "--script",
            "deploy",
            "--key",
            "abc123",
            "var1",
            "var2",
        ])
        .unwrap();
        assert_eq!(args.address, "wss://host");
        assert_eq!(args.script, "deploy");
        assert_eq!(args.key, "abc123");
        assert_eq!(args.variables, vec!["var1".to_string(), "var2".to_string()]);
    }

    #[test]
    fn defaults_log_level_to_info_and_chunk_size_to_65536() {
        let args = CliArguments::try_parse_from([
            "orosu-client",
            "--address",
            "a",
            "--script",
            "s",
            "--key",
            "k",
        ])
        .unwrap();
        assert_eq!(args.log_level, LogLevelConfiguration::Info);
        assert_eq!(args.chunk_size, 65536);
        assert!(args.file.is_none());
        assert!(args.retries.is_none());
        assert!(args.variables.is_empty());
    }

    #[test]
    fn rejects_a_missing_required_address() {
        let result = CliArguments::try_parse_from(["orosu-client", "--script", "s", "--key", "k"]);
        assert!(result.is_err());
    }

    #[test]
    fn parses_short_flags() {
        let args = CliArguments::try_parse_from([
            "orosu-client",
            "-a",
            "addr",
            "-s",
            "script",
            "-k",
            "key",
            "-c",
            "1024",
            "-l",
            "debug",
        ])
        .unwrap();
        assert_eq!(args.address, "addr");
        assert_eq!(args.chunk_size, 1024);
        assert_eq!(args.log_level, LogLevelConfiguration::Debug);
    }

    #[test]
    fn rejects_an_invalid_log_level() {
        let result = CliArguments::try_parse_from([
            "orosu-client",
            "--address",
            "a",
            "--script",
            "s",
            "--key",
            "k",
            "--log-level",
            "not-a-level",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn parses_multiple_file_flags_into_a_vec() {
        let args = CliArguments::try_parse_from([
            "orosu-client",
            "--address",
            "a",
            "--script",
            "s",
            "--key",
            "k",
            "--file",
            "one.txt",
            "--file",
            "two.txt",
        ])
        .unwrap();
        assert_eq!(
            args.file,
            Some(vec!["one.txt".to_string(), "two.txt".to_string()])
        );
    }

    #[test]
    fn parses_retries() {
        let args = CliArguments::try_parse_from([
            "orosu-client",
            "--address",
            "a",
            "--script",
            "s",
            "--key",
            "k",
            "--retries",
            "5",
        ])
        .unwrap();
        assert_eq!(args.retries, Some(5));
    }
}
