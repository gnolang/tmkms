//! Integration tests for the `yubihsm help` subcommand

use crate::cli;

/// `README.yubihsm.md` tells operators to run `tmkms yubihsm help` and check the
/// output against a sample. A sample that drifts from the program turns that
/// check into a false negative, so the two are pinned together here.
#[test]
fn the_documented_output_is_what_the_command_prints() {
    let readme = std::fs::read_to_string("README.yubihsm.md").unwrap();
    let out = cli::run_successfully(["yubihsm", "help"]);

    assert_eq!(
        documented_output(&readme),
        String::from_utf8(out.stdout).unwrap()
    );
}

/// The sample output from the fenced block, without the prompt line that shows
/// which command produced it.
fn documented_output(readme: &str) -> String {
    let after_prompt = readme
        .split_once("$ tmkms yubihsm help\n")
        .expect("the README should show a `tmkms yubihsm help` invocation")
        .1;

    let block = after_prompt
        .split_once("\n```")
        .expect("the sample output should sit in a fenced block")
        .0;

    format!("{block}\n")
}
