//! `tmkms softsign keygen` subcommand

use crate::{error::Error, key_utils, prelude::*};
use abscissa_core::Command;
use clap::Parser;
use k256::ecdsa;
use rand_core::{OsRng, RngCore};
use std::{path::Path, path::PathBuf, process};
use zeroize::Zeroizing;

/// Default type of key to generate
pub const DEFAULT_KEY_TYPE: &str = "consensus";

/// `keygen` command
#[derive(Command, Debug, Default, Parser)]
pub struct KeygenCommand {
    /// type of key: 'account' or 'consensus' (default 'consensus')
    #[clap(short = 't', long = "type")]
    key_type: Option<String>,

    /// path where generated key should be created
    output_paths: Vec<PathBuf>,
}

impl Runnable for KeygenCommand {
    /// Generate an Ed25519 secret key for use with a software provider (i.e. ed25519-dalek)
    fn run(&self) {
        if self.output_paths.len() != 1 {
            eprintln!("Usage: tmkms softsign keygen [-t account,consensus] PATH");
            process::exit(1);
        }

        let output_path = &self.output_paths[0];

        let generated = match self
            .key_type
            .as_ref()
            .map(AsRef::as_ref)
            .unwrap_or(DEFAULT_KEY_TYPE)
        {
            "account" => generate_secp256k1_key(output_path),
            "consensus" => generate_ed25519_key(output_path),
            other => {
                status_err!(
                    "unknown key type: {} (must be 'account' or 'consensus')",
                    other
                );
                process::exit(1);
            }
        };

        // Exit only here, once the generator has returned and dropped the key:
        // `process::exit` runs no destructors, so nothing would wipe it
        if let Err(e) = generated {
            status_err!("{}", e);
            process::exit(1);
        }
    }
}

/// Randomly generate a Base64-encoded secp256k1 key and store it at the given path
fn generate_secp256k1_key(output_path: &Path) -> Result<(), Error> {
    let signing_key = ecdsa::SigningKey::random(&mut OsRng);
    // `to_bytes` hands back a copy of the private scalar
    let secret_bytes = Zeroizing::new(signing_key.to_bytes());

    key_utils::write_base64_secret(output_path, &secret_bytes)?;

    status_ok!(
        "Generated",
        "account (secp256k1) private key at: {}",
        output_path.display()
    );
    Ok(())
}

/// Randomly generate a Base64-encoded Ed25519 key and store it at the given path
fn generate_ed25519_key(output_path: &Path) -> Result<(), Error> {
    // `Zeroizing` wipes the seed when this scope ends; `SigningKey` zeroizes
    // itself on drop, but the buffer it was built from would otherwise be left
    // in place
    let mut sk_bytes = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(sk_bytes.as_mut());
    // `from(&[u8; 32])` borrows, where `from(*sk_bytes)` would copy the seed onto
    // the stack and leave that copy unwiped
    let sk = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);

    key_utils::write_base64_secret(output_path, sk.as_bytes())?;

    status_ok!(
        "Generated",
        "consensus (Ed25519) private key at: {}",
        output_path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `process::exit` runs no destructors, so a write failure that ended the process
    /// where it happened would skip wiping the key just generated. It must come back to
    /// `run` instead, after the key has been dropped.
    #[test]
    fn a_failed_write_comes_back_to_run() {
        let dir = tempfile::tempdir().unwrap();
        let unwritable = dir.path().join("missing/key");

        for generate in [generate_secp256k1_key, generate_ed25519_key] {
            assert_eq!(
                generate(&unwritable).unwrap_err().to_string(),
                format!(
                    "I/O error: couldn't write `{}`: No such file or directory (os error 2)",
                    unwritable.display()
                )
            );
        }
    }
}
