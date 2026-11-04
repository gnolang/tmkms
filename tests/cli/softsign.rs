//! Integration tests for the `softsign` subcommands

use crate::cli;
use std::{fs, os::unix::fs::PermissionsExt, str};
use tmkms::key_utils;

/// A priv_validator key file holding an Ed25519 key
const ED25519_PRIV_VALIDATOR_PATH: &str = "tests/support/priv_validator_mock.json";

/// A priv_validator key file holding a secp256k1 key
const SECP256K1_PRIV_VALIDATOR_PATH: &str = "tests/support/priv_validator_secp256k1_mock.json";

/// Run `tmkms softsign` with `args`, and return its exit code and what it wrote to
/// stdout and stderr, with the colour codes removed
fn softsign(args: &[&str]) -> (Option<i32>, String, String) {
    let out = cli::run(["softsign"].iter().chain(args));
    let plain = |stream: &[u8]| cli::without_colour_codes(str::from_utf8(stream).unwrap());
    (out.status.code(), plain(&out.stdout), plain(&out.stderr))
}

/// The permission bits of the file at `path`
fn mode(path: &str) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// Every outcome of `softsign keygen`: the exit code and every line it prints
#[test]
fn keygen_reports_every_outcome() {
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name).display().to_string();
    let (consensus_key, account_key) = (path("consensus.key"), path("account.key"));
    let unwritable = path("missing/key");
    let write_error = format!(
        "error: I/O error: couldn't write `{unwritable}`: No such file or directory (os error 2)\n"
    );

    let cases: Vec<(Vec<&str>, Option<i32>, String)> = vec![
        (
            vec!["keygen"],
            Some(1),
            "Usage: tmkms softsign keygen [-t account,consensus] PATH\n".into(),
        ),
        (
            vec!["keygen", "-t", "bogus", &consensus_key],
            Some(1),
            "error: unknown key type: bogus (must be 'account' or 'consensus')\n".into(),
        ),
        (vec!["keygen", &unwritable], Some(1), write_error.clone()),
        (
            vec!["keygen", "-t", "account", &unwritable],
            Some(1),
            write_error,
        ),
        (
            vec!["keygen", &consensus_key],
            Some(0),
            format!("   Generated consensus (Ed25519) private key at: {consensus_key}\n"),
        ),
        (
            vec!["keygen", "-t", "account", &account_key],
            Some(0),
            format!("   Generated account (secp256k1) private key at: {account_key}\n"),
        ),
    ];

    for (args, code, stderr) in cases {
        assert_eq!(softsign(&args), (code, String::new(), stderr), "{args:?}");
    }

    assert_eq!((mode(&consensus_key), mode(&account_key)), (0o600, 0o600));
    key_utils::load_signing_key(&consensus_key).unwrap();
    key_utils::load_base64_secp256k1_key(&account_key).unwrap();
}

/// Every outcome of `softsign import`: the exit code and every line it prints
#[test]
fn import_reports_every_outcome() {
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name).display().to_string();
    let (ed25519_json, secp256k1_json) =
        (ED25519_PRIV_VALIDATOR_PATH, SECP256K1_PRIV_VALIDATOR_PATH);
    let (missing_json, output, unwritable) = (
        path("missing.json"),
        path("output.key"),
        path("missing/key"),
    );
    let write_error = format!(
        "error: I/O error: couldn't write `{unwritable}`: No such file or directory (os error 2)\n"
    );

    let failures: Vec<(Vec<&str>, String)> = vec![
        (
            vec!["import", ed25519_json],
            "error: expected 2 arguments, got 1\n\n\
             Usage: tmkms softsign import [priv_validator.json] [output.key]\n"
                .into(),
        ),
        (
            vec!["import", "-f", "bogus", ed25519_json, &output],
            "error: config error: invalid key format: bogus (must be 'json' or 'raw')\n".into(),
        ),
        (
            vec!["import", "-f", "raw", ed25519_json, &output],
            "error: config error: invalid key format: raw (must be 'json' or 'raw')\n".into(),
        ),
        (
            vec!["import", "-f", "base64", ed25519_json, &output],
            "error: invalid format: Base64 (must be 'json')\n".into(),
        ),
        (
            vec!["import", &missing_json, &output],
            format!(
                "error: couldn't load {missing_json}: StringTracer: failed to open file: \
                 {missing_json}: No such file or directory (os error 2)\n"
            ),
        ),
        (
            vec!["import", ed25519_json, &unwritable],
            write_error.clone(),
        ),
        (vec!["import", secp256k1_json, &unwritable], write_error),
    ];

    for (args, stderr) in failures {
        assert_eq!(
            softsign(&args),
            (Some(1), String::new(), stderr),
            "{args:?}"
        );
    }

    for (json, key, algorithm) in [
        (ed25519_json, path("ed25519.key"), "Ed25519"),
        (secp256k1_json, path("secp256k1.key"), "Secp256k1"),
    ] {
        let (code, stdout, stderr) = softsign(&["import", json, &key]);
        let logged = format!(
            "  INFO tmkms::commands::softsign::import: Imported {algorithm} private key to {key}\n"
        );

        assert_eq!((code, stderr.as_str()), (Some(0), ""), "{json}");
        assert!(
            stdout.ends_with(&logged) && stdout.lines().count() == 1,
            "{stdout}"
        );
        assert_eq!(mode(&key), 0o600);
    }

    key_utils::load_signing_key(path("ed25519.key")).unwrap();
    key_utils::load_base64_secp256k1_key(path("secp256k1.key")).unwrap();
}
