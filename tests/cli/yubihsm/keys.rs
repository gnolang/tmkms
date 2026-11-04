//! Integration tests for the `yubihsm keys` subcommand

mod generate;
mod import;
mod list;

#[cfg(feature = "yubihsm-mock")]
pub use super::KMS_CONFIG_PATH;
pub use super::{PRIV_VALIDATOR_CONFIG_PATH, SECP256K1_PRIV_VALIDATOR_PATH};
use crate::cli;

#[test]
fn test_usage() {
    let status_code = cli::run(["yubihsm", "keys"]).status.code().unwrap();
    assert_eq!(status_code, 2);
}
