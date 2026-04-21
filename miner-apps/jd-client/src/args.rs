use clap::Parser;
use ext_config::{Config, File, FileFormat};
use jd_client_sv2::{config::JobDeclaratorClientConfig, error::JDCErrorKind};
use stratum_apps::config_helpers::secret_key_from_env;

use std::path::PathBuf;
use tracing::{error, warn};
#[derive(Debug, Parser)]
#[command(author, version, about = "JD Client", long_about = None)]
pub struct Args {
    #[arg(
        short = 'c',
        long = "config",
        help = "Path to the TOML configuration file",
        default_value = "jdc-config.toml"
    )]
    pub config_path: PathBuf,
    #[arg(
        short = 'f',
        long = "log-file",
        help = "Path to the log file. If not set, logs will only be written to stdout."
    )]
    pub log_file: Option<PathBuf>,
}

#[allow(clippy::result_large_err)]
pub fn process_cli_args() -> Result<JobDeclaratorClientConfig, JDCErrorKind> {
    let args = Args::parse();

    let config_path = args.config_path.to_str().ok_or_else(|| {
        error!("Invalid configuration path.");
        JDCErrorKind::BadCliArgs
    })?;

    let settings = Config::builder()
        .add_source(File::new(config_path, FileFormat::Toml))
        .build()?;

    let mut config = settings.try_deserialize::<JobDeclaratorClientConfig>()?;

    let env_secret_key = secret_key_from_env("JDC_AUTHORITY_SECRET_KEY").map_err(|e| {
        error!("Failed to parse JDC_AUTHORITY_SECRET_KEY: {}", e);
        JDCErrorKind::BadCliArgs
    })?;

    let authority_secret_key = match (&env_secret_key, config.authority_secret_key()) {
        (Some(env_key), Some(toml_key)) => {
            warn!("Both JDC_AUTHORITY_SECRET_KEY env var and config file have authority secret key. Using env var value. Consider removing the key from your config file.");
            env_key.clone()
        }
        (Some(env_key), None) => env_key.clone(),
        (None, Some(toml_key)) => toml_key.clone(),
        (None, None) => {
            error!("No authority secret key found. Set JDC_AUTHORITY_SECRET_KEY env var or configure authority_secret_key in the config file.");
            return Err(JDCErrorKind::BadCliArgs);
        }
    };

    config.set_authority_secret_key(authority_secret_key);

    config.set_log_file(args.log_file);

    Ok(config)
}
