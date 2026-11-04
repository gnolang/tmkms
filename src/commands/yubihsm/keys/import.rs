//! Import keys either from encrypted backups or existing plaintext keys

use super::{DEFAULT_DOMAINS, DEFAULT_WRAP_KEY};
use crate::{key_utils, keyring::ed25519, prelude::*};
use abscissa_core::Command;
use clap::Parser;
use cometbft::{PrivateKey, PublicKey};
use cometbft_config::PrivValidatorKey;
use std::{fs, path::PathBuf, process};
use subtle_encoding::base64;
use yubihsm::{Client, object};
use zeroize::Zeroizing;

/// The `yubihsm keys import` subcommand
#[derive(Command, Debug, Default, Parser)]
pub struct ImportCommand {
    /// path to tmkms.toml
    #[clap(short = 'c', long = "config")]
    pub config: Option<PathBuf>,

    /// key ID to import
    #[clap(short = 'i', long = "id")]
    pub key_id: Option<u16>,

    /// wrap key to decrypt with
    #[clap(short = 'w', long = "wrapkey")]
    pub wrap_key_id: Option<u16>,

    /// type of key to import (wrap, base64 or json)
    #[clap(short = 't')]
    pub key_type: Option<String>,

    /// label for priv_validator keys
    #[clap(short = 'l', long = "label")]
    pub label: Option<String>,

    /// path to key to import
    pub path: PathBuf,
}

/// What `yubihsm keys import` reports when the key's import needs a key ID it wasn't given
const NO_KEY_ID: &str =
    "no key ID specified (use e.g. tmkms yubihsm keys import -i 1 priv_validator.json)";

impl Runnable for ImportCommand {
    fn run(&self) {
        // Connecting to the HSM ends the process when it fails, so connect before any
        // secret is in memory
        let hsm = crate::yubihsm::client();

        // Exit only here, once `import` has returned and dropped every secret it held:
        // `process::exit` runs no destructors, so nothing would wipe them
        if let Err(message) = self.import(&hsm) {
            status_err!("{}", message);
            process::exit(1);
        }
    }
}

impl ImportCommand {
    /// Import the key file, returning what went wrong as the message the operator reads
    pub fn import(&self, hsm: &Client) -> Result<(), String> {
        // The file holds key material, so wipe the buffer when this scope ends
        let contents = Zeroizing::new(
            fs::read_to_string(&self.path)
                .map_err(|e| format!("couldn't import file {}: {}", self.path.display(), e))?,
        );

        match self.key_type.as_deref() {
            Some("wrap") => self.import_wrapped(hsm, &contents),
            Some("json") => self.import_priv_validator_json(hsm, &contents),
            Some("base64") => self.import_base64(hsm, &contents),
            Some(other) => Err(format!("invalid key type: {other}")),
            None => {
                if self.path.ends_with("priv_validator_key.json") {
                    self.import_priv_validator_json(hsm, &contents)
                } else {
                    self.import_wrapped(hsm, &contents)
                }
            }
        }
    }

    /// Import a wrapped object into the HSM
    fn import_wrapped(&self, hsm: &Client, wrapped_key_base64: &str) -> Result<(), String> {
        if let Some(id) = self.key_id {
            status_warn!("ignoring key ID: {} (wrapped keys use original key ID)", id);
        }

        if let Some(ref label) = self.label {
            status_warn!(
                "ignoring label: {:?} (wrapped keys use original label)",
                label
            );
        }

        let wrap_key_id = self.wrap_key_id.unwrap_or(DEFAULT_WRAP_KEY);

        let wrapped_key_ciphertext =
            base64::decode(wrapped_key_base64.as_bytes()).map_err(|e| {
                format!(
                    "couldn't decode Base64-encoded wrapped key from {}: {}",
                    self.path.display(),
                    e
                )
            })?;

        let wrapped_message =
            yubihsm::wrap::Message::from_vec(wrapped_key_ciphertext).map_err(|e| {
                format!(
                    "couldn't parse wrapped key from {}: {}",
                    self.path.display(),
                    e
                )
            })?;

        let obj = hsm
            .import_wrapped(wrap_key_id, wrapped_message)
            .map_err(|e| {
                format!(
                    "error importing encrypted key from {} (using wrapkey 0x{:04x}): {}",
                    self.path.display(),
                    wrap_key_id,
                    e
                )
            })?;

        if obj.object_type != object::Type::AsymmetricKey {
            // We mainly care about importing asymmetric keys, but can handle other types.
            // If we encounter a non-asymmetric key type, display basic info.
            status_ok!(
                "Imported",
                "object 0x{:04x} ({:?})",
                obj.object_id,
                obj.object_type
            );
            return Ok(());
        }

        let public_key = hsm.get_public_key(obj.object_id).map_err(|e| {
            format!(
                "couldn't get public key for asymmetric key #{}: {}",
                obj.object_id, e
            )
        })?;

        // TODO: display non hex format when listing/displaying keys
        let key_info = match public_key.algorithm {
            yubihsm::asymmetric::Algorithm::Ed25519 => {
                PublicKey::from_raw_ed25519(public_key.as_ref())
                    .unwrap()
                    .to_hex()
            }
            alg => format!("{:?}: {:?}", alg, public_key.as_ref()),
        };

        status_ok!("Imported", "key 0x{:04x}: {}", obj.object_id, key_info);
        Ok(())
    }

    /// Import an existing priv_validator file into the HSM
    fn import_priv_validator_json(&self, hsm: &Client, json_data: &str) -> Result<(), String> {
        let key_id = self.ed25519_key_id()?;

        let private_key = PrivValidatorKey::parse_json(json_data)
            .map_err(|e| format!("couldn't parse priv_validator key: {e}"))?
            .priv_key;

        // `PrivValidatorKey` also accepts secp256k1, so this is reachable with a
        // legitimate key file
        let PrivateKey::Ed25519(seed) = private_key else {
            return Err(format!(
                "unsupported key type in `{}`: an Ed25519 consensus key is required",
                self.path.display()
            ));
        };

        self.put_ed25519_seed(hsm, key_id, seed.as_bytes())
    }

    /// Import a Base64-encoded private key into the HSM
    fn import_base64(&self, hsm: &Client, base64_data: &str) -> Result<(), String> {
        let key_id = self.ed25519_key_id()?;

        let key_bytes = key_utils::decode_base64_secret(base64_data)
            .map_err(|e| format!("can't decode Ed25519 key: {e}"))?;

        let secret = ed25519::SigningKey::try_from(key_bytes.as_ref())
            .map_err(|e| format!("invalid Ed25519 key: {e}"))?;

        let seed_bytes = secret
            .as_bytes()
            .ok_or("Ed25519 key must be provided as a 32-byte seed")?;

        self.put_ed25519_seed(hsm, key_id, seed_bytes)
    }

    /// The key ID to import an Ed25519 key as, warning that a wrap key ID applies only
    /// to wrapped keys
    fn ed25519_key_id(&self) -> Result<u16, String> {
        if let Some(id) = self.wrap_key_id {
            status_warn!(
                "ignoring wrapkey ID: {} (not applicable to priv_validator.json files)",
                id
            );
        }

        self.key_id.ok_or_else(|| NO_KEY_ID.to_owned())
    }

    /// Put an Ed25519 seed into the HSM as key `key_id`
    fn put_ed25519_seed(&self, hsm: &Client, key_id: u16, seed: &[u8]) -> Result<(), String> {
        let label = object::Label::from(self.label.as_deref().unwrap_or(""));

        hsm.put_asymmetric_key(
            key_id,
            label,
            DEFAULT_DOMAINS,
            yubihsm::Capability::SIGN_EDDSA | yubihsm::Capability::EXPORTABLE_UNDER_WRAP,
            yubihsm::asymmetric::Algorithm::Ed25519,
            seed,
        )
        .map_err(|e| format!("couldn't import key #{key_id}: {e}"))?;

        status_ok!("Imported", "key 0x{:04x}", key_id);
        Ok(())
    }
}

#[cfg(all(test, feature = "yubihsm-mock"))]
mod tests {
    use super::*;
    use std::path::Path;
    use yubihsm::{Connector, Credentials};

    /// How the HSM behind `failing_hsm` ends its refusal of every command; what comes
    /// before names a session number, which varies
    const HSM_REFUSAL: &str = "invalid credentials for authentication key #1 (cryptogram mismatch)";

    /// A mock HSM client with the wrong password, so every command it sends fails
    fn failing_hsm() -> Client {
        Client::create(
            Connector::mockhsm(),
            Credentials::from_password(1, b"wrong"),
        )
        .unwrap()
    }

    /// A command importing the file at `path` as `key_type`
    fn import_command(key_type: &str, key_id: Option<u16>, path: &Path) -> ImportCommand {
        ImportCommand {
            key_id,
            key_type: Some(key_type.to_owned()),
            path: path.to_owned(),
            ..Default::default()
        }
    }

    /// `process::exit` runs no destructors, so a failure that ended the process where it
    /// happened would skip wiping the file buffer and any key already decoded. Each one
    /// must come back to `run` instead, after those have been dropped.
    #[test]
    fn failures_come_back_to_run() {
        let hsm = failing_hsm();
        let dir = tempfile::tempdir().unwrap();
        let file = |name: &str, contents: &str| {
            let path = dir.path().join(name);
            fs::write(&path, contents).unwrap();
            path
        };
        let not_base64 = file("not_base64", "not base64!");
        let short_wrap = file("short_wrap", "AAAAAAAAAAAAAAAA");
        let empty_json = file("empty.json", "{}");
        let short_key = file("short_key", "AAAAAAAAAAAAAAAAAAAAAA==");
        let expanded_key = file("expanded_key", &format!("{}==", "A".repeat(86)));
        let secp256k1_json = Path::new("tests/support/priv_validator_secp256k1_mock.json");
        let seed = Path::new("tests/support/signing_ed25519.key");
        let no_key_id =
            "no key ID specified (use e.g. tmkms yubihsm keys import -i 1 priv_validator.json)";

        let cases = [
            (
                import_command("bogus", None, &not_base64),
                "invalid key type: bogus".to_owned(),
            ),
            (
                import_command("wrap", None, &not_base64),
                format!(
                    "couldn't decode Base64-encoded wrapped key from {}: bad encoding",
                    not_base64.display()
                ),
            ),
            (
                import_command("wrap", None, &short_wrap),
                format!(
                    "couldn't parse wrapped key from {}: \
                     invalid message length: message must be at least 13-bytes",
                    short_wrap.display()
                ),
            ),
            (
                import_command("json", None, secp256k1_json),
                no_key_id.to_owned(),
            ),
            (
                import_command("json", Some(1), &empty_json),
                "couldn't parse priv_validator key: \
                 StringTracer: serde json error: missing field `address` at line 1 column 2"
                    .to_owned(),
            ),
            (
                import_command("json", Some(1), secp256k1_json),
                format!(
                    "unsupported key type in `{}`: an Ed25519 consensus key is required",
                    secp256k1_json.display()
                ),
            ),
            (import_command("base64", None, seed), no_key_id.to_owned()),
            (
                import_command("base64", Some(1), &not_base64),
                "can't decode Ed25519 key: bad encoding".to_owned(),
            ),
            (
                import_command("base64", Some(1), &short_key),
                "invalid Ed25519 key: \
                 invalid key: invalid Ed25519 key size: expected 32, 64, or 96, but got 16"
                    .to_owned(),
            ),
            (
                import_command("base64", Some(1), &expanded_key),
                "Ed25519 key must be provided as a 32-byte seed".to_owned(),
            ),
        ];

        for (command, message) in cases {
            assert_eq!(command.import(&hsm), Err(message));
        }
    }

    /// The HSM's own failures come once the key is decoded, so they must come back to
    /// `run` too
    #[test]
    fn hsm_failures_come_back_to_run() {
        let hsm = failing_hsm();
        let dir = tempfile::tempdir().unwrap();
        let wrapped = dir.path().join("wrapped");
        fs::write(&wrapped, format!("{}=", "A".repeat(43))).unwrap();
        let json = Path::new("tests/support/priv_validator_mock.json");
        let seed = Path::new("tests/support/signing_ed25519.key");

        let cases = [
            (
                import_command("json", Some(1), json),
                "couldn't import key #1: ".to_owned(),
            ),
            (
                import_command("base64", Some(1), seed),
                "couldn't import key #1: ".to_owned(),
            ),
            (
                import_command("wrap", None, &wrapped),
                format!(
                    "error importing encrypted key from {} (using wrapkey 0x0001): ",
                    wrapped.display()
                ),
            ),
        ];

        for (command, reason) in cases {
            let message = command.import(&hsm).unwrap_err();
            assert!(
                message.starts_with(&reason) && message.ends_with(HSM_REFUSAL),
                "{message}"
            );
        }
    }
}
