use std::path::PathBuf;

#[derive(Debug, clap::Parser)]
#[command(version, about, long_about = None)]
pub struct CliArguments {
    #[cfg_attr(
        target_os = "linux",
        clap(
            short,
            long,
            env = "CONFIG_FILE",
            default_value = "/etc/orosu/config.yaml"
        )
    )]
    #[cfg_attr(not(target_os = "linux"), clap(short, long, env = "CONFIG_FILE"))]
    pub config_file_path: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_the_long_flag() {
        let args =
            CliArguments::try_parse_from(["orosu-server", "--config-file-path", "/tmp/c.yaml"])
                .unwrap();
        assert_eq!(args.config_file_path, PathBuf::from("/tmp/c.yaml"));
    }

    #[test]
    fn parses_the_short_flag() {
        let args = CliArguments::try_parse_from(["orosu-server", "-c", "/tmp/short.yaml"]).unwrap();
        assert_eq!(args.config_file_path, PathBuf::from("/tmp/short.yaml"));
    }

    // Deliberately not tested here: the /etc/orosu/config.yaml default and
    // the CONFIG_FILE env-var fallback. clap resolves both by reading the
    // real process environment — global mutable state shared across every
    // test in this binary, and `std::env::set_var` is `unsafe` as of this
    // workspace's 2024 edition specifically because mutating it races with
    // other threads. Not exercising it here is a deliberate call to avoid
    // flaky tests, not an oversight.
}
