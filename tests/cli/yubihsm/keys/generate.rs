//! Integration tests for the `yubihsm keys generate` subcommand

use crate::cli;
use std::str;

#[test]
fn keys_generate_command_test() {
    #[allow(unused_mut)]
    let mut args = vec!["yubihsm", "keys", "generate", "1"];

    #[cfg(feature = "yubihsm-mock")]
    args.extend_from_slice(&["-c", super::KMS_CONFIG_PATH]);

    let cmd_out = cli::run_successfully(args.as_slice());
    assert!(cmd_out.status.success());

    let stderr = str::from_utf8(&cmd_out.stderr).unwrap().trim().to_owned();
    assert!(stderr.contains("Generated"));
    assert!(stderr.contains("key 0x0001"));
}

/// `-p gpub` prints the legacy layout, which gno.land cannot decode, so the
/// command says so even though it never reads a chain's `key_format`
#[cfg(feature = "yubihsm-mock")]
#[test]
fn warns_on_a_gno_prefix() {
    let cmd_out = cli::run_successfully([
        "yubihsm",
        "keys",
        "generate",
        "2",
        "-p",
        "gpub",
        "-c",
        super::KMS_CONFIG_PATH,
    ]);

    let stderr = str::from_utf8(&cmd_out.stderr).unwrap();

    assert!(
        stderr.contains("gno.land cannot decode"),
        "expected a gno prefix warning, got: {stderr}"
    );
    assert!(
        stderr.contains("key 0x0002"),
        "the key must still be printed, got: {stderr}"
    );
}

/// Any other prefix is a chain's own business, so the command stays quiet
#[cfg(feature = "yubihsm-mock")]
#[test]
fn does_not_warn_on_another_prefix() {
    let cmd_out = cli::run_successfully([
        "yubihsm",
        "keys",
        "generate",
        "3",
        "-p",
        "cosmosvalconspub",
        "-c",
        super::KMS_CONFIG_PATH,
    ]);

    let stderr = str::from_utf8(&cmd_out.stderr).unwrap();

    assert!(
        !stderr.contains("gno.land cannot decode"),
        "a non-gno prefix must not warn, got: {stderr}"
    );
    assert!(stderr.contains("key 0x0003"), "got: {stderr}");
}
