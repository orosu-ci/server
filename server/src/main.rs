mod arguments;

use crate::arguments::CliArguments;
use anyhow::Context;
use clap::Parser;
use orosu::configuration::Configuration;
use orosu::cryptography::ServerStaticKey;
use orosu::server;
use server::Server;
use tracing::level_filters::LevelFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    _ = dotenvy::dotenv();

    let arguments = CliArguments::parse();

    let configuration = Configuration::from_file(&arguments.config_file_path)
        .context("unable to load configuration file")?;

    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::from_level(configuration.log_level.into()))
        .compact()
        .init();

    tracing::debug!("Starting Orosu server");

    let encryption_key = configuration
        .encryption_key_file
        .as_ref()
        .map(|path| ServerStaticKey::from_file(path))
        .transpose()
        .context("unable to load encryption key file")?;

    let server = Server::new(
        configuration.listen,
        configuration.ip_whitelist,
        configuration.ip_blacklist,
        configuration.clients,
        encryption_key,
    );

    server.serve().await?;

    Ok(())
}
