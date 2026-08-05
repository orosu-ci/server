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

fn write_or_print(
    label: &str,
    value: String,
    output: Option<std::path::PathBuf>,
) -> anyhow::Result<()> {
    match output {
        Some(path) => {
            std::fs::write(&path, value)?;
            println!("{label} written to {}", path.display());
        }
        None => {
            println!("{label}: {value}");
        }
    };
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let arguments = CliArguments::parse();

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

    write_or_print("Private key", private_key, arguments.private_key_output)?;
    write_or_print("Public key", public_key, arguments.public_key_output)?;

    Ok(())
}
