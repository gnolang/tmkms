//! Integration tests for the `yubihsm keys list` subcommand

use crate::cli;
use std::str;

#[test]
fn keys_command_test() {
    #[allow(unused_mut)]
    let mut args = vec!["yubihsm", "keys", "list"];

    #[cfg(feature = "yubihsm-mock")]
    args.extend_from_slice(&["-c", super::KMS_CONFIG_PATH]);

    let out = cli::run_successfully(args.as_slice());

    assert!(out.status.success());
    assert!(out.stdout.is_empty());

    let stderr = str::from_utf8(&out.stderr).unwrap().trim().to_owned();
    assert!(stderr.contains("no keys in this YubiHSM"));
}

/// A Bech32 `gpub` consensus prefix prints a key gno.land cannot decode, so
/// listing keys warns about it the way starting the KMS does
#[cfg(feature = "yubihsm-mock")]
#[test]
fn warns_on_a_gno_prefix() {
    let out = cli::run_successfully([
        "yubihsm",
        "keys",
        "list",
        "-c",
        super::super::KMS_GNO_PREFIX_CONFIG_PATH,
    ]);

    let stderr = str::from_utf8(&out.stderr).unwrap();

    assert!(
        stderr.contains("gno.land cannot decode"),
        "expected a gno prefix warning, got: {stderr}"
    );
}
