//! Utilities

use crate::{
    error::{Error, ErrorKind::*},
    keyring::ed25519,
    prelude::*,
};
use k256::ecdsa;
use rand_core::{OsRng, RngCore};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};
use subtle_encoding::{Base64, Encoding, base64};
use zeroize::Zeroizing;

/// File permissions for secret data
pub const SECRET_FILE_PERMS: u32 = 0o600;

/// Returns true if the given Unix mode grants read access beyond the owner
fn is_readable_by_others(mode: u32) -> bool {
    mode & 0o077 != 0
}

/// Warn if a secret file is readable by users other than its owner.
///
/// This warns rather than refusing to load: by the time a key file is exposed the
/// secrecy is already lost, and failing here would take a validator offline
/// without recovering it.
fn warn_if_readable_by_others(path: &Path) {
    match fs::metadata(path) {
        Ok(metadata) => {
            let mode = metadata.permissions().mode() & 0o777;

            if is_readable_by_others(mode) {
                warn!(
                    "{} is readable by users other than its owner (mode {:04o}): \
                     restrict it with `chmod 600`",
                    path.display(),
                    mode
                );
            }
        }
        Err(e) => warn!("couldn't check permissions of {}: {}", path.display(), e),
    }
}

/// Decode a Base64-encoded secret, ignoring trailing whitespace such as a final
/// newline. The decoder writes every group before it reports an invalid one, so it
/// decodes into a buffer that is wiped when dropped, whether or not decoding succeeds.
pub fn decode_base64_secret(encoded: &str) -> Result<Zeroizing<Vec<u8>>, subtle_encoding::Error> {
    // TODO(tarcieri): constant-time string trimming
    let encoded = encoded.trim_end().as_bytes();

    let mut decoded = Zeroizing::new(vec![0u8; Base64::default().decoded_len(encoded)?]);
    let decoded_len = Base64::default().decode_to_slice(encoded, &mut decoded)?;
    decoded.truncate(decoded_len);

    Ok(decoded)
}

/// Load Base64-encoded secret data (i.e. key) from the given path
pub fn load_base64_secret(path: impl AsRef<Path>) -> Result<Zeroizing<Vec<u8>>, Error> {
    warn_if_readable_by_others(path.as_ref());

    let base64_data = Zeroizing::new(fs::read_to_string(path.as_ref()).map_err(|e| {
        format_err!(
            IoError,
            "couldn't read key from {}: {}",
            path.as_ref().display(),
            e
        )
    })?);

    decode_base64_secret(&base64_data).map_err(|e| {
        format_err!(
            IoError,
            "can't decode key from `{}`: {}",
            path.as_ref().display(),
            e
        )
        .into()
    })
}

/// Load a Base64-encoded Ed25519 secret key
pub fn load_identity_key(path: impl AsRef<Path>) -> Result<ed25519_dalek::SigningKey, Error> {
    let key_bytes = load_base64_secret(path)?;

    let signing_key = ed25519::SigningKey::try_from(key_bytes.as_slice())
        .map_err(|e| format_err!(InvalidKey, "invalid Ed25519 key: {}", e))?;

    let seed = signing_key.as_bytes().ok_or_else(|| {
        format_err!(
            InvalidKey,
            "Ed25519 identity key must be provided as a 32-byte seed"
        )
    })?;

    Ok(ed25519_dalek::SigningKey::from_bytes(seed))
}

/// Load a Base64-encoded Ed25519 secret key
pub fn load_signing_key(path: impl AsRef<Path>) -> Result<ed25519::SigningKey, Error> {
    let key_bytes = load_base64_secret(path)?;

    ed25519::SigningKey::try_from(key_bytes.as_slice())
}

/// Load a Base64-encoded Secp256k1 secret key
pub fn load_base64_secp256k1_key(
    path: impl AsRef<Path>,
) -> Result<(ecdsa::SigningKey, ecdsa::VerifyingKey), Error> {
    let key_bytes = load_base64_secret(path)?;

    let signing = ecdsa::SigningKey::try_from(key_bytes.as_slice())
        .map_err(|e| format_err!(InvalidKey, "invalid ECDSA key: {}", e))?;

    let verifying = ecdsa::VerifyingKey::from(&signing);

    Ok((signing, verifying))
}

/// Store Base64-encoded secret data at the given path
pub fn write_base64_secret(path: impl AsRef<Path>, data: &[u8]) -> Result<(), Error> {
    let base64_data = Zeroizing::new(base64::encode(data));

    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(SECRET_FILE_PERMS)
        .open(path.as_ref())
        .and_then(|mut file| {
            // `OpenOptions::mode` only applies to a file this call creates, so an
            // existing file keeps whatever permissions it already had. Tighten the
            // open handle before writing, so the secret is never on disk with
            // permissive modes.
            file.set_permissions(fs::Permissions::from_mode(SECRET_FILE_PERMS))?;
            file.write_all(&base64_data)
        })
        .map_err(|e| {
            format_err!(
                IoError,
                "couldn't write `{}`: {}",
                path.as_ref().display(),
                e
            )
            .into()
        })
}

/// Generate a Secret Connection key at the given path
pub fn generate_key(path: impl AsRef<Path>) -> Result<(), Error> {
    let mut secret_key = Zeroizing::new([0u8; ed25519::SigningKey::BYTE_SIZE]);
    OsRng.fill_bytes(&mut *secret_key);
    write_base64_secret(path, &*secret_key)
}

#[cfg(test)]
mod tests {
    use super::{SECRET_FILE_PERMS, is_readable_by_others, write_base64_secret};
    use std::{fs, os::unix::fs::PermissionsExt};

    fn mode_of(path: &std::path::Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn secret_written_to_a_new_file_is_not_readable_by_others() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new.key");

        write_base64_secret(&path, b"secret key material").unwrap();

        assert_eq!(mode_of(&path), SECRET_FILE_PERMS);
    }

    #[test]
    fn secret_written_over_a_world_readable_file_tightens_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("existing.key");
        fs::write(&path, b"old contents").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        write_base64_secret(&path, b"secret key material").unwrap();

        assert_eq!(
            mode_of(&path),
            SECRET_FILE_PERMS,
            "a pre-existing file must not keep permissive modes once a secret is written to it"
        );
    }

    #[test]
    fn owner_only_modes_are_not_readable_by_others() {
        for mode in [0o600, 0o400, 0o700] {
            assert!(!is_readable_by_others(mode), "{mode:04o}");
        }
    }

    #[test]
    fn group_or_world_readable_modes_are_detected() {
        for mode in [0o640, 0o604, 0o644, 0o660, 0o777, 0o606] {
            assert!(is_readable_by_others(mode), "{mode:04o}");
        }
    }
}
