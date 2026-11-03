//! Validator configuration

use crate::{
    error::{Error, ErrorKind::ConfigError},
    prelude::*,
};
use cometbft::chain;
use cometbft_config::net;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Validator configuration
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorConfig {
    /// Address of the validator (`tcp://` or `unix://`)
    pub addr: net::Address,

    /// Chain ID of the Tendermint network this validator is part of
    pub chain_id: chain::Id,

    /// Automatically reconnect on error? (default: true)
    #[serde(default = "reconnect_default")]
    pub reconnect: bool,

    /// Optional timeout value in seconds
    pub timeout: Option<u16>,

    /// Path to our Ed25519 identity key (if applicable)
    pub secret_key: Option<PathBuf>,

    /// Height at which to stop signing
    pub max_height: Option<cometbft::block::Height>,

    /// Deprecated: legacy protocol version number. Must be v0.34 if present.
    // TODO(tarcieri): remove this completely? Here for backwards compatibility.
    pub protocol_version: Option<ProtocolVersion>,

    /// Connect to a `tcp://` validator address that carries no `@peer_id`,
    /// leaving the validator unauthenticated? (default: false)
    #[serde(default)]
    pub allow_unverified_peer: bool,
}

impl ValidatorConfig {
    /// Check that this validator will be cryptographically authenticated.
    ///
    /// A `tcp://` address with no `@peer_id` prefix means the signer will talk to
    /// whatever answers at that address. An unauthenticated peer can drive the
    /// double signing protection state forward and deny signing for the real
    /// validator, so skipping verification requires an explicit opt-in.
    pub fn validate_peer_verification(&self) -> Result<(), Error> {
        if self.allow_unverified_peer {
            return Ok(());
        }

        if let net::Address::Tcp {
            peer_id: None,
            host,
            port,
        } = &self.addr
        {
            fail!(
                ConfigError,
                "[{}] validator address `tcp://{}:{}` has no peer ID, so the validator cannot be \
                 authenticated: prefix the address with `<peer_id>@`, or set \
                 `allow_unverified_peer = true` to accept an unauthenticated peer",
                self.chain_id,
                host,
                port
            );
        }

        Ok(())
    }
}

/// Protocol version (based on the Tendermint version)
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum ProtocolVersion {
    /// Tendermint v0.38
    #[default]
    #[serde(rename = "v0.38")]
    V0_38,

    /// Legacy: Tendermint v0.34
    #[serde(rename = "v0.34")]
    V0_34,
}

/// Default value for the `ValidatorConfig` reconnect field
fn reconnect_default() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::ValidatorConfig;

    const EXAMPLE_PEER_ID: &str = "d1b82bbd8f2cf01c5e8f451da43dce9b369c86a9";

    fn config_with(addr: &str, extra: &str) -> ValidatorConfig {
        serde_json::from_str(&format!(
            r#"{{"addr":"{addr}","chain_id":"test-chain"{extra}}}"#
        ))
        .unwrap()
    }

    #[test]
    fn tcp_address_without_peer_id_is_rejected() {
        let config = config_with("tcp://127.0.0.1:26658", "");

        config
            .validate_peer_verification()
            .expect_err("a TCP validator with no peer ID must be rejected");
    }

    #[test]
    fn tcp_address_without_peer_id_is_allowed_when_opted_in() {
        let config = config_with("tcp://127.0.0.1:26658", r#","allow_unverified_peer":true"#);

        config.validate_peer_verification().unwrap();
    }

    #[test]
    fn tcp_address_with_peer_id_is_allowed() {
        let config = config_with(&format!("tcp://{EXAMPLE_PEER_ID}@127.0.0.1:26658"), "");

        config.validate_peer_verification().unwrap();
    }

    #[test]
    fn unix_address_is_unaffected() {
        let config = config_with("unix:///tmp/tmkms.sock", "");

        config.validate_peer_verification().unwrap();
    }
}
