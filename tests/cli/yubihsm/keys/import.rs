//! Integration tests for the `yubihsm keys import` subcommand

use crate::cli;
use std::str;

#[test]
fn keys_import_priv_validator_test() {
    #[allow(unused_mut)]
    let mut args = vec!["yubihsm", "keys", "import"];

    #[cfg(feature = "yubihsm-mock")]
    args.extend_from_slice(&["-c", super::KMS_CONFIG_PATH]);
    args.extend_from_slice(&["-t", "json"]);
    args.extend_from_slice(&["-i", "1"]); // key ID
    args.extend_from_slice(&[super::PRIV_VALIDATOR_CONFIG_PATH]);

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
    #[allow(unused_mut)]
    let mut args = vec!["yubihsm", "keys", "import"];

    #[cfg(feature = "yubihsm-mock")]
    args.extend_from_slice(&["-c", super::KMS_CONFIG_PATH]);
    args.extend_from_slice(&["-t", "json"]);
    args.extend_from_slice(&["-i", "1"]); // key ID
    args.extend_from_slice(&[super::SECP256K1_PRIV_VALIDATOR_PATH]);

    let out = cli::run(args.as_slice());
    let message = str::from_utf8(&out.stderr).unwrap();

    assert_eq!(out.status.code(), Some(1), "{message}");
    assert!(
        message.contains("Ed25519 consensus key is required"),
        "{message}"
    );
}
