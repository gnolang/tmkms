//! `tmkms softsign import` command

use crate::{config::provider::softsign::KeyFormat, error::Error, key_utils, prelude::*};
use abscissa_core::Command;
use clap::Parser;
use cometbft::PrivateKey;
use cometbft_config::PrivValidatorKey;
use std::{
    path::{Path, PathBuf},
    process,
};
use zeroize::Zeroizing;

/// `import` command: import a `priv_validator.json` formatted key and convert
/// it into the raw format used by the softsign backend (by default)
#[derive(Command, Debug, Default, Parser)]
pub struct ImportCommand {
    /// key format to import: 'json' or 'raw' (default 'json')
    #[clap(short = 'f')]
    format: Option<String>,

    /// [INPUT] and [OUTPUT] paths for key generation
    paths: Vec<PathBuf>,
}

impl Runnable for ImportCommand {
    /// Import a `priv_validator.json`
    fn run(&self) {
        if self.paths.len() != 2 {
            status_err!("expected 2 arguments, got {}", self.paths.len());
            eprintln!("\nUsage: tmkms softsign import [priv_validator.json] [output.key]");
            process::exit(1);
        }

        let input_path = &self.paths[0];
        let output_path = &self.paths[1];

        let format = self
            .format
            .as_ref()
            .map(|f| {
                f.parse::<KeyFormat>().unwrap_or_else(|e| {
                    status_err!("{} (must be 'json' or 'raw')", e);
                    process::exit(1);
                })
            })
            .unwrap_or(KeyFormat::Json);

        if format != KeyFormat::Json {
            status_err!("invalid format: {:?} (must be 'json')", format);
            process::exit(1);
        }

        let secret_key = PrivValidatorKey::load_json_file(input_path)
            .unwrap_or_else(|e| {
                status_err!("couldn't load {}: {}", input_path.display(), e);
                process::exit(1);
            })
            .priv_key;

        // Exit only here, once `write_secret_key` has returned and dropped the key:
        // `process::exit` runs no destructors, so nothing would wipe it
        match write_secret_key(secret_key, output_path) {
            Ok(algorithm) => info!(
                "Imported {} private key to {}",
                algorithm,
                output_path.display()
            ),
            Err(e) => {
                status_err!("{}", e);
                process::exit(1);
            }
        }
    }
}

/// Write `secret_key` to `output_path` in the softsign format, and return the name of
/// its algorithm
fn write_secret_key(secret_key: PrivateKey, output_path: &Path) -> Result<&'static str, Error> {
    match secret_key {
        PrivateKey::Ed25519(sk) => {
            key_utils::write_base64_secret(output_path, sk.as_bytes())?;
            Ok("Ed25519")
        }
        PrivateKey::Secp256k1(sk) => {
            // `to_bytes` hands back a copy of the private scalar
            let secret_bytes = Zeroizing::new(sk.to_bytes());
            key_utils::write_base64_secret(output_path, &secret_bytes)?;
            Ok("Secp256k1")
        }
        _ => unreachable!("unsupported priv_validator.json algorithm"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `process::exit` runs no destructors, so a write failure that ended the process
    /// where it happened would skip wiping the imported key. It must come back to `run`
    /// instead, after the key has been dropped.
    #[test]
    fn a_failed_write_comes_back_to_run() {
        let dir = tempfile::tempdir().unwrap();
        let unwritable = dir.path().join("missing/key");

        for key_file in [
            "tests/support/priv_validator_mock.json",
            "tests/support/priv_validator_secp256k1_mock.json",
        ] {
            let secret_key = PrivValidatorKey::load_json_file(&key_file)
                .unwrap()
                .priv_key;

            assert_eq!(
                write_secret_key(secret_key, &unwritable)
                    .unwrap_err()
                    .to_string(),
                format!(
                    "I/O error: couldn't write `{}`: No such file or directory (os error 2)",
                    unwritable.display()
                )
            );
        }
    }
}
