//! Tests for the KMS command-line interface

use std::{
    ffi::OsStr,
    process::{Command, Output},
};

use super::KMS_EXE_PATH;

mod init;
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
#[allow(dead_code)]
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

#[test]
fn test_usage() {
    let status_code = run(&[] as &[&OsStr]).status.code().unwrap();
    assert_eq!(status_code, 2);
}
