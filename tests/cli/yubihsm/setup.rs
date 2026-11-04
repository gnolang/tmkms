//! Integration tests for the `yubihsm setup` subcommand, against the mock HSM

use crate::cli;
use std::{
    fs,
    io::{Read, Write},
    process::{Command, Stdio},
    str,
};

/// A valid 24-word admin mnemonic, so that everything derived from it is known
const MNEMONIC: &str = "abandon amount liar amount expire adjust cage candy arch gather drum \
                        bullet absurd math era live bid rhythm alien crouch range attend journey \
                        unaware";

/// What setup prints before it reads the mnemonic to restore
const RESTORE_PROMPT: &str = "Restoring and reprovisioning YubiHSM from existing 24-word \
                              mnemonic phrase.\n\n\
                              *** Enter mnemonic (separate words with spaces): ";

/// What setup prints once it has read a valid mnemonic
const MNEMONIC_DECODED: &str = "\nMnemonic phrase decoded/checksummed successfully!\n\n";

/// What setup prints before it lists the keys it would install
const ERASE_WARNING: &str = "This process will *ERASE* the configured YubiHSM2 and \
                             reinitialize it:\n\n\
                             - YubiHSM serial: 0123456789\n\n\
                             Authentication keys with the following IDs and passwords will be \
                             created:\n\n";

/// The mnemonic and the keys derived from `MNEMONIC`, as setup lists them
const DERIVED_KEYS: &str = "- key 0x0001: admin:\n\n    \
    abandon amount liar amount expire adjust cage candy arch gather drum bullet\n    \
    absurd math era live bid rhythm alien crouch range attend journey unaware\n\n\
    - authkey 0x0002 [operator]:  kms-operator-password-1ztuhkpagag6tp9tptl9qma2wcuzsvyff\n\
    - authkey 0x0003 [auditor]:   kms-auditor-password-16zukfrl5lcs4tg9udcvv98fzfsx9zluq\n\
    - authkey 0x0004 [validator]: kms-validator-password-168w265r9rr9gjr3wu4j0dtzhkyadyy04\n\
    - wrapkey 0x0001 [primary]:   \
    b55c675289521f334d544ff62f1860af42d62814a5233a16174faff5d46fbe7e\n";

/// The question setup asks before it erases the HSM
const CONFIRMATION: &str = "\n*** Are you SURE you want erase and reinitialize this HSM? (y/N): ";

/// Run `yubihsm setup` against the mock HSM with `options`, typing `stdin` into it, and
/// return its exit code and what it wrote to stdout and stderr, with the colour codes
/// removed
fn setup(options: &[&str], stdin: &str) -> (Option<i32>, String, String) {
    let args = ["yubihsm", "setup", "-c", super::KMS_CONFIG_PATH];
    let out = cli::run_with_stdin(args.iter().chain(options), stdin);
    let plain = |stream: &[u8]| cli::without_colour_codes(str::from_utf8(stream).unwrap());
    (out.status.code(), plain(&out.stdout), plain(&out.stderr))
}

#[test]
fn setup_prints_the_keys_it_derives_from_a_restored_mnemonic() {
    assert_eq!(
        setup(&["-r", "-p"], &format!("{MNEMONIC}\n")),
        (
            Some(0),
            format!(
                "{RESTORE_PROMPT}{MNEMONIC_DECODED}Below are all keys/passwords derived from \
                 your 24-word admin mnemonic:\n\n{DERIVED_KEYS}"
            ),
            String::new()
        )
    );
}

#[test]
fn setup_refuses_a_mnemonic_it_cannot_decode() {
    assert_eq!(
        setup(&["-r"], "not a mnemonic\n"),
        (
            Some(1),
            RESTORE_PROMPT.to_owned(),
            "*** ERROR: Couldn't decode mnemonic\n".to_owned()
        )
    );
}

#[test]
fn setup_stops_when_the_erase_is_not_confirmed() {
    assert_eq!(
        setup(&["-r"], &format!("{MNEMONIC}\nn\n")),
        (
            Some(1),
            format!(
                "{RESTORE_PROMPT}{MNEMONIC_DECODED}{ERASE_WARNING}{DERIVED_KEYS}{CONFIRMATION}\
                 Aborting\n"
            ),
            String::new()
        )
    );
}

#[test]
fn setup_reinitializes_the_hsm_when_the_erase_is_confirmed() {
    let (code, stdout, stderr) = setup(&["-r"], &format!("{MNEMONIC}\ny\n"));
    let before_erase =
        format!("{RESTORE_PROMPT}{MNEMONIC_DECODED}{ERASE_WARNING}{DERIVED_KEYS}{CONFIRMATION}");

    assert_eq!(
        (code, stderr.as_str()),
        (
            Some(0),
            "     Success reinitialized YubiHSM (serial: 0123456789)\n"
        ),
        "{stdout}"
    );
    assert!(stdout.starts_with(&before_erase), "{stdout}");
    assert!(stdout.contains("installing wrap key: primary:"), "{stdout}");
}

/// Setup reads the HSM password file before it derives any secret. Reading it fails by
/// ending the process, so a read after that point would skip wiping every secret.
#[test]
fn setup_reads_its_password_file_before_deriving_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let password_file = dir.path().join("password");
    fs::write(&password_file, "password\n").unwrap();
    let config = dir.path().join("tmkms.toml");
    let mock_config = fs::read_to_string(super::KMS_CONFIG_PATH).unwrap();
    let password_line = r#"auth = { key = 1, password = "password" }"#;
    assert!(mock_config.contains(password_line));
    fs::write(
        &config,
        mock_config.replace(
            password_line,
            &format!(
                r#"auth = {{ key = 1, password_file = "{}" }}"#,
                password_file.display()
            ),
        ),
    )
    .unwrap();

    let mut setup = Command::new(crate::KMS_EXE_PATH)
        .args(["yubihsm", "setup", "-c", config.to_str().unwrap(), "-r"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = setup.stdin.take().unwrap();
    let mut stdout = setup.stdout.take().unwrap();
    stdin.write_all(format!("{MNEMONIC}\n").as_bytes()).unwrap();

    // Once setup asks to confirm, every secret exists: take the password file away
    let mut printed = Vec::new();
    let mut byte = [0];
    while !printed.ends_with(CONFIRMATION.as_bytes()) && stdout.read(&mut byte).unwrap() == 1 {
        printed.push(byte[0]);
    }
    fs::remove_file(&password_file).unwrap();
    stdin.write_all(b"y\n").unwrap();
    drop(stdin);
    stdout.read_to_end(&mut printed).unwrap();

    let out = setup.wait_with_output().unwrap();
    let stderr = cli::without_colour_codes(str::from_utf8(&out.stderr).unwrap());
    assert_eq!(
        (out.status.code(), stderr.as_str()),
        (
            Some(0),
            "     Success reinitialized YubiHSM (serial: 0123456789)\n"
        ),
        "{}",
        String::from_utf8_lossy(&printed)
    );
}
