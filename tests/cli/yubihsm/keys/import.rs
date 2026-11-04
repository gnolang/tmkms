//! Integration tests for the `yubihsm keys import` subcommand

use crate::cli;
use std::{fs, path::Path, str};
use subtle_encoding::base64;
use tempfile::TempDir;

/// Arguments to run `yubihsm keys import` with `options`
fn import_args<'a>(options: &[&'a str]) -> Vec<&'a str> {
    #[allow(unused_mut)]
    let mut args = vec!["yubihsm", "keys", "import"];

    #[cfg(feature = "yubihsm-mock")]
    args.extend_from_slice(&["-c", super::KMS_CONFIG_PATH]);
    args.extend_from_slice(options);
    args
}

/// Arguments to import the given priv_validator key file as key 0x0001
fn import_json_args(path: &str) -> Vec<&str> {
    import_args(&["-t", "json", "-i", "1", path])
}

/// Run `yubihsm keys import` with `options`, and return its exit code and what it
/// wrote to stderr with the colour codes removed
fn import(options: &[&str]) -> (Option<i32>, String) {
    run_writing_only_stderr(&import_args(options))
}

/// Run `tmkms` with `args`, check that it wrote nothing to stdout, and return its exit
/// code and what it wrote to stderr with the colour codes removed
fn run_writing_only_stderr(args: &[&str]) -> (Option<i32>, String) {
    let out = cli::run(args);
    assert_eq!(
        str::from_utf8(&out.stdout).unwrap(),
        "",
        "stdout of {args:?}"
    );

    let stderr = str::from_utf8(&out.stderr).unwrap();
    (out.status.code(), cli::without_colour_codes(stderr))
}

/// Write `contents` to a file named `name` in `dir` and return its path
fn key_file(dir: &TempDir, name: &str, contents: &str) -> String {
    let path = dir.path().join(name);
    fs::write(&path, contents).unwrap();
    path.display().to_string()
}

/// `len` zero bytes, Base64-encoded
fn zeros_base64(len: usize) -> String {
    String::from_utf8(base64::encode(vec![0; len])).unwrap()
}

/// Every outcome of `yubihsm keys import` that needs no real HSM: the exit code and
/// every line the operator reads, for each key type and each way the import fails
#[test]
fn keys_import_reports_every_outcome() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing").display().to_string();
    let not_base64 = key_file(&dir, "not_base64", "not base64!");
    let short_wrap = key_file(&dir, "short_wrap", &zeros_base64(12));
    let unknown_wrap = key_file(&dir, "unknown_wrap", &zeros_base64(32));
    let empty_json = key_file(&dir, "empty.json", "{}");
    let short_key = key_file(&dir, "short_key", &zeros_base64(16));
    let expanded_key = key_file(&dir, "expanded_key", &zeros_base64(64));
    let json = super::PRIV_VALIDATOR_CONFIG_PATH;
    let json_by_name = key_file(
        &dir,
        "priv_validator_key.json",
        &fs::read_to_string(json).unwrap(),
    );
    let seed = "tests/support/signing_ed25519.key";
    assert!(Path::new(seed).exists());

    let no_key_id = "error: no key ID specified (use e.g. tmkms yubihsm keys import -i 1 priv_validator.json)\n";
    let wrapkey_ignored =
        "warning: ignoring wrapkey ID: 5 (not applicable to priv_validator.json files)\n";
    let unknown_wrap_error = format!(
        "error: error importing encrypted key from {unknown_wrap} (using wrapkey 0x0001): HSM error: HSM error: invalid command\n"
    );

    let cases: Vec<(Vec<&str>, Option<i32>, String)> = vec![
        // Any key type
        (
            vec!["-t", "json", &missing],
            Some(1),
            format!(
                "error: couldn't import file {missing}: No such file or directory (os error 2)\n"
            ),
        ),
        (
            vec!["-t", "bogus", &not_base64],
            Some(1),
            "error: invalid key type: bogus\n".into(),
        ),
        // Wrapped keys, the default for a file not named priv_validator_key.json
        (
            vec![&not_base64],
            Some(1),
            format!(
                "error: couldn't decode Base64-encoded wrapped key from {not_base64}: bad encoding\n"
            ),
        ),
        (
            vec!["-t", "wrap", &short_wrap],
            Some(1),
            format!(
                "error: couldn't parse wrapped key from {short_wrap}: \
                 invalid message length: message must be at least 13-bytes\n"
            ),
        ),
        (
            vec!["-t", "wrap", &unknown_wrap],
            Some(1),
            unknown_wrap_error.clone(),
        ),
        (
            vec!["-t", "wrap", "-i", "5", "-l", "foo", &unknown_wrap],
            Some(1),
            format!(
                "warning: ignoring key ID: 5 (wrapped keys use original key ID)\n\
                 warning: ignoring label: \"foo\" (wrapped keys use original label)\n\
                 {unknown_wrap_error}"
            ),
        ),
        // priv_validator JSON keys, the default for a file named priv_validator_key.json
        (vec![&json_by_name], Some(1), no_key_id.into()),
        (vec!["-t", "json", json], Some(1), no_key_id.into()),
        (
            vec!["-t", "json", "-i", "1", &empty_json],
            Some(1),
            "error: couldn't parse priv_validator key: \
             StringTracer: serde json error: missing field `address` at line 1 column 2\n"
                .into(),
        ),
        (
            vec!["-t", "json", "-i", "1", "-w", "5", json],
            Some(0),
            format!("{wrapkey_ignored}    Imported key 0x0001\n"),
        ),
        // Base64 keys
        (vec!["-t", "base64", seed], Some(1), no_key_id.into()),
        (
            vec!["-t", "base64", "-i", "1", &not_base64],
            Some(1),
            "error: can't decode Ed25519 key: bad encoding\n".into(),
        ),
        (
            vec!["-t", "base64", "-i", "1", &short_key],
            Some(1),
            "error: invalid Ed25519 key: \
             invalid key: invalid Ed25519 key size: expected 32, 64, or 96, but got 16\n"
                .into(),
        ),
        (
            vec!["-t", "base64", "-i", "1", &expanded_key],
            Some(1),
            "error: Ed25519 key must be provided as a 32-byte seed\n".into(),
        ),
        (
            vec!["-t", "base64", "-i", "1", "-w", "5", seed],
            Some(0),
            format!("{wrapkey_ignored}    Imported key 0x0001\n"),
        ),
    ];

    for (args, code, stderr) in cases {
        assert_eq!(import(&args), (code, stderr), "{args:?}");
    }
}

#[test]
fn keys_import_priv_validator_test() {
    let args = import_json_args(super::PRIV_VALIDATOR_CONFIG_PATH);

    let out = cli::run_successfully(args.as_slice());

    assert!(out.status.success());

    let message = str::from_utf8(&out.stderr).unwrap().trim().to_owned();
    assert!(message.contains("key 0x0001"));
}

/// A priv_validator key file can hold a secp256k1 key, which cannot be imported as
/// an Ed25519 consensus key: that has to be an error the operator can act on, not
/// a panic
#[test]
fn keys_import_rejects_a_secp256k1_priv_validator() {
    let args = import_json_args(super::SECP256K1_PRIV_VALIDATOR_PATH);

    let out = cli::run(args.as_slice());
    let message = str::from_utf8(&out.stderr).unwrap();

    assert_eq!(out.status.code(), Some(1), "{message}");
    assert!(
        message.contains("Ed25519 consensus key is required"),
        "{message}"
    );
    assert!(
        message.contains(super::SECP256K1_PRIV_VALIDATOR_PATH),
        "{message}"
    );
}

/// Connecting to the HSM ends the process when it fails, and nothing wipes what is in
/// memory then, so the import connects before it reads the key file
#[test]
fn keys_import_connects_before_reading_the_key_file() {
    let dir = tempfile::tempdir().unwrap();
    let config_without_hsm = key_file(&dir, "tmkms.toml", "[providers]\n");
    let missing_key = dir.path().join("missing").display().to_string();

    let args = [
        "yubihsm",
        "keys",
        "import",
        "-c",
        &config_without_hsm,
        "-t",
        "base64",
        "-i",
        "1",
        &missing_key,
    ];

    assert_eq!(
        run_writing_only_stderr(&args),
        (
            Some(1),
            "error: expected one [[providers.yubihsm]] in config, found: 0\n".to_owned()
        )
    );
}
