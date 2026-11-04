//! Tests for the KMS command-line interface

use std::{
    ffi::OsStr,
    process::{Command, Output},
};

use super::KMS_EXE_PATH;

mod init;
#[cfg(feature = "softsign")]
mod softsign;
mod version;

#[cfg(feature = "yubihsm")]
mod yubihsm;

/// Run the `tmkms` CLI command with the given arguments
pub fn run<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(KMS_EXE_PATH).args(args).output().unwrap()
}

/// Run the `tmkms` CLI command with the expectation that it will exit successfully,
/// panicking with its stdout and stderr if it does not
pub fn run_successfully<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = run(args);

    if output.status.success() {
        output
    } else {
        // Carried in the panic rather than written to the real stdout: that way
        // the test harness attributes it to the failing test, the two streams
        // cannot interleave, and a command killed by a signal still reports
        panic!(
            "{KMS_EXE_PATH} {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// Nothing else exercises the failure branch: every other caller expects to
/// succeed, so without this the reporting path is only ever read by someone who
/// already has a failing test.
///
/// What it pins: the exit-status branch, and the stderr half of the report —
/// the half that carries `tmkms`'s diagnostics. What it does not: the signal
/// branch, which needs a command that dies from a signal, so replacing
/// `status.success()` with `status.code().unwrap()` still passes here; and the
/// stdout half, which can be dropped without failing it.
#[test]
#[should_panic(expected = "--- stderr ---")]
fn a_failed_command_is_reported_with_both_streams() {
    run_successfully(["not-a-real-subcommand"]);
}

/// `text` without the ANSI colour codes `tmkms` writes even when not on a terminal
pub fn without_colour_codes(text: &str) -> String {
    let mut plain = String::new();
    let mut chars = text.chars();

    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // A colour code runs from the escape character to the next `m`
            chars.by_ref().find(|&c| c == 'm');
        } else {
            plain.push(c);
        }
    }

    plain
}

#[test]
fn test_usage() {
    let status_code = run(&[] as &[&OsStr]).status.code().unwrap();
    assert_eq!(status_code, 2);
}
