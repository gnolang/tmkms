//! State hook support: obtain `ConsensusState` from an external source

use crate::{
    config::chain::HookConfig,
    error::{Error, ErrorKind::HookError},
    prelude::*,
};
use cometbft::block;
use serde::Deserialize;
use std::{
    io::Read,
    process::{Command, Stdio},
    thread,
    time::Duration,
};
use wait_timeout::ChildExt;

/// Default timeout to use when a user one is unspecified
const DEFAULT_TIMEOUT_SECS: u64 = 1;

/// Sanity limit on how far the block height from the hook can diverge from the
/// last known state
pub const BLOCK_HEIGHT_SANITY_LIMIT: u64 = 9000;

/// Run the given hook command to obtain the last signing state
pub fn run(config: &HookConfig) -> Result<Output, Error> {
    let (program, args) = match config.cmd.split_first() {
        Some(split) => split,
        None => fail!(HookError, "no command given in state hook config"),
    };

    // Stdout must be piped for the JSON output to be readable
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .spawn()?;

    // Drained while the hook runs rather than once it exits: a hook that writes
    // more than the pipe holds blocks on that write until something reads it
    let mut stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => fail!(HookError, "couldn't consume stdout from child"),
    };
    let reader = thread::Builder::new()
        .name("state-hook-output".to_owned())
        .spawn(move || {
            let mut output = Vec::new();
            stdout.read_to_end(&mut output).map(|_| output)
        })?;

    let timeout = Duration::from_secs(config.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS));

    match child.wait_timeout(timeout)? {
        Some(status) => {
            if status.success() {
                let output = match reader.join() {
                    Ok(read) => read?,
                    Err(_) => fail!(HookError, "couldn't read the hook's output"),
                };
                Ok(serde_json::from_slice(&output)?)
            } else {
                fail!(HookError, "subcommand returned status {:?}", status.code())
            }
        }
        None => {
            // timeout
            child.kill()?;
            child.wait()?;
            fail!(HookError, "subcommand timed out after {:?}", timeout)
        }
    }
}

/// JSON output from the hook command (parsed with serde)
#[derive(Debug, Deserialize)]
pub struct Output {
    /// Latest block height
    pub latest_block_height: block::Height,
}

#[cfg(test)]
mod tests {
    use crate::{config::chain::HookConfig, error::ErrorKind};

    /// Build a config for a hook that runs the given shell snippet
    fn shell_hook(script: &str) -> HookConfig {
        HookConfig {
            cmd: vec!["/bin/sh".to_owned(), "-c".to_owned(), script.to_owned()],
            timeout_secs: Some(5),
            fail_closed: true,
        }
    }

    #[test]
    fn reads_latest_block_height_from_hook_stdout() {
        let output = super::run(&shell_hook("echo '{\"latest_block_height\":\"12345\"}'"))
            .expect("hook should produce output");

        assert_eq!(output.latest_block_height.value(), 12345);
    }

    /// Nothing may wait on the hook to exit before draining its stdout: a hook
    /// that writes more than a pipe holds blocks on the write, never exits, and
    /// the run would be reported as a timeout instead of read
    #[test]
    fn a_hook_writing_more_than_a_pipe_holds_is_still_read() {
        // A mebibyte of leading whitespace, past any platform's pipe buffer,
        // then the JSON a hook is expected to print
        let output = super::run(&shell_hook(
            "head -c 1048576 /dev/zero | tr '\\0' ' '; echo '{\"latest_block_height\":\"5\"}'",
        ))
        .expect("a large but well-formed output should be read");

        assert_eq!(output.latest_block_height.value(), 5);
    }

    #[test]
    fn nonzero_exit_status_is_an_error() {
        let err = super::run(&shell_hook("exit 3")).expect_err("expected hook failure");

        assert_eq!(*err.kind(), ErrorKind::HookError);
    }

    #[test]
    fn empty_command_is_an_error_not_a_panic() {
        let config = HookConfig {
            cmd: vec![],
            timeout_secs: Some(5),
            fail_closed: true,
        };

        let err = super::run(&config).expect_err("expected an error for an empty command");

        assert_eq!(*err.kind(), ErrorKind::HookError);
    }

    #[test]
    fn command_exceeding_the_timeout_is_an_error() {
        let mut config = shell_hook("sleep 5");
        config.timeout_secs = Some(1);

        let err = super::run(&config).expect_err("expected a timeout error");

        assert_eq!(*err.kind(), ErrorKind::HookError);
    }
}
