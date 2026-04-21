//! CLI argument parsing for the Pool binary.
//!
//! Defines the `Args` struct and a function to process CLI arguments into a PoolConfig.

use clap::Parser;
use ext_config::{Config, File, FileFormat};
use pool_sv2::config::PoolConfig;
use std::path::PathBuf;
use stratum_apps::config_helpers::secret_key_from_env;
use tracing::warn;

/// Holds the parsed CLI arguments for the Pool binary.
#[derive(Parser, Debug)]
#[command(author, version, about = "Pool CLI", long_about = None)]
pub struct Args {
    #[arg(
        short = 'c',
        long = "config",
        help = "Path to the TOML configuration file",
        default_value = "pool-config.toml"
    )]
    pub config_path: PathBuf,
    #[arg(
        short = 'f',
        long = "log-file",
        help = "Path to the log file. If not set, logs will only be written to stdout."
    )]
    pub log_file: Option<PathBuf>,
}

#[cfg_attr(not(test), hotpath::measure)]
/// Parses CLI arguments and loads the PoolConfig from the specified file.
pub fn process_cli_args() -> PoolConfig {
    let args = Args::parse();
    let config_path = args.config_path.to_str().expect("Invalid config path");
    let mut config: PoolConfig = Config::builder()
        .add_source(File::new(config_path, FileFormat::Toml))
        .build()
        .and_then(|settings| settings.try_deserialize::<PoolConfig>())
        .expect("Failed to load or deserialize config");

    let env_key = secret_key_from_env("POOL_AUTHORITY_SECRET_KEY")
        .expect("Failed to read POOL_AUTHORITY_SECRET_KEY env var");

    if let Some(key) = env_key {
        if config.authority_secret_key_opt().is_some() {
            warn!("Both POOL_AUTHORITY_SECRET_KEY env var and config file have authority secret key. Using env var value. Consider removing the key from your config file.");
        }
        config.set_authority_secret_key(key);
    } else if config.authority_secret_key_opt().is_none() {
        panic!("Authority secret key not set. Set POOL_AUTHORITY_SECRET_KEY env var or authority_secret_key in config file.");
    }

    config.set_log_dir(args.log_file);

    config
}
