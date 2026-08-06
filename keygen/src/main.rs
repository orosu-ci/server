use crate::arguments::{CliArguments, KeyKind};
use clap::Parser;
use orosu::cryptography::{Keygen, ServerKeygen};
use std::io;
use std::io::Write;

mod arguments;

fn prompt_input(prompt: &str) -> anyhow::Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

/// Whether a written file should be restricted to owner-only access. Public
/// keys are meant to be shared, so they're written with the process's
/// default (umask-controlled) permissions; private keys are secrets and
/// must not depend on the umask being configured safely.
enum WritePermissions {
    Default,
    OwnerOnly,
}

#[cfg(unix)]
fn restrict_to_owner(path: &std::path::Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn write_or_print(
    label: &str,
    value: String,
    output: Option<std::path::PathBuf>,
    permissions: WritePermissions,
) -> anyhow::Result<()> {
    match output {
        Some(path) => {
            std::fs::write(&path, value)?;
            #[cfg(unix)]
            if matches!(permissions, WritePermissions::OwnerOnly) {
                restrict_to_owner(&path)?;
            }
            #[cfg(not(unix))]
            let _ = permissions;
            println!("{label} written to {}", path.display());
        }
        None => {
            println!("{label}: {value}");
        }
    };
    Ok(())
}

/// Rejects `--private-key-output`/`--public-key-output` pointing at the
/// same path. Without this, writing the private key first and the public
/// key second (main's actual write order) would silently overwrite the
/// private key file with the public key — the operator walks away
/// believing they have a private key file when they don't, discovered only
/// later when authentication fails.
fn validate_output_paths(arguments: &CliArguments) -> anyhow::Result<()> {
    if let (Some(private), Some(public)) =
        (&arguments.private_key_output, &arguments.public_key_output)
        && private == public
    {
        anyhow::bail!(
            "--private-key-output and --public-key-output must not be the same path ({}); \
             writing both would silently overwrite the private key with the public key",
            private.display()
        );
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let arguments = CliArguments::parse();
    validate_output_paths(&arguments)?;

    let (private_key, public_key) = match arguments.kind {
        KeyKind::Client => {
            // Bare `orosu-keygen` behavior, unchanged: a named client
            // identity key, prompting for a name if one wasn't given.
            let name = match arguments.name {
                Some(name) => name,
                None => prompt_input("Name: ")?,
            };
            let keygen = Keygen::new(name);
            (keygen.private_key_base64(), keygen.public_key_base64())
        }
        KeyKind::Server => {
            // One identity per orosu-server instance, not per client — no
            // name to prompt for.
            let keygen = ServerKeygen::new();
            (keygen.private_key_base64(), keygen.public_key_base64())
        }
    };

    write_or_print(
        "Private key",
        private_key,
        arguments.private_key_output,
        WritePermissions::OwnerOnly,
    )?;
    write_or_print(
        "Public key",
        public_key,
        arguments.public_key_output,
        WritePermissions::Default,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn owner_only_output_is_written_with_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private.key");

        write_or_print(
            "Private key",
            "shh".to_string(),
            Some(path.clone()),
            WritePermissions::OwnerOnly,
        )
        .unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn default_output_does_not_restrict_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("public.key");
        // Start from a mode `write_or_print` would never itself produce, so
        // a passing test proves Default really is a no-op rather than
        // coincidentally landing on the same bits some other way.
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();

        write_or_print(
            "Public key",
            "not-a-secret".to_string(),
            Some(path.clone()),
            WritePermissions::Default,
        )
        .unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o666);
    }

    fn args_with_outputs(private: &str, public: &str) -> CliArguments {
        CliArguments::try_parse_from([
            "orosu-keygen",
            "--private-key-output",
            private,
            "--public-key-output",
            public,
        ])
        .unwrap()
    }

    #[test]
    fn rejects_identical_private_and_public_output_paths() {
        let args = args_with_outputs("same.key", "same.key");
        assert!(validate_output_paths(&args).is_err());
    }

    #[test]
    fn allows_distinct_output_paths() {
        let args = args_with_outputs("priv.key", "pub.key");
        assert!(validate_output_paths(&args).is_ok());
    }

    #[test]
    fn allows_omitted_output_paths() {
        let args = CliArguments::try_parse_from(["orosu-keygen"]).unwrap();
        assert!(validate_output_paths(&args).is_ok());
    }

    // Only writing one of the two outputs is fine even if the other is
    // omitted — there's no clobbering risk when only one file is written.
    #[test]
    fn allows_only_one_output_path_set() {
        let args =
            CliArguments::try_parse_from(["orosu-keygen", "--private-key-output", "only.key"])
                .unwrap();
        assert!(validate_output_paths(&args).is_ok());
    }
}
