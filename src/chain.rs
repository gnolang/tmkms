//! Information about particular Tendermint blockchain networks

mod guard;
mod registry;
pub mod state;

pub use self::{
    guard::Guard,
    registry::{GlobalRegistry, REGISTRY, Registry},
    state::State,
};
use crate::{
    config::{KmsConfig, chain::ChainConfig},
    error::{Error, ErrorKind},
    keyring::{self, KeyRing},
    prelude::*,
};
pub use cometbft::chain::Id;
use std::{
    path::{self, Path, PathBuf},
    sync::Mutex,
};

/// Information about a particular Tendermint blockchain network
pub struct Chain {
    /// ID of a particular chain
    pub id: Id,

    /// Should extensions for this chain be signed?
    pub sign_extensions: bool,

    /// Signing keyring for this chain
    pub keyring: KeyRing,

    /// State from the last block signed for this chain
    pub state: Mutex<State>,
}

impl Chain {
    /// Attempt to create a `Chain` state from the given configuration
    pub fn from_config(config: &ChainConfig) -> Result<Chain, Error> {
        let state_file = resolve_state_file_path(config.state_file.as_deref(), &config.id)?;

        let (mut state, outcome) = State::load_state(&state_file)?;

        match outcome {
            state::LoadOutcome::Loaded => info!(
                "[{}] loaded consensus state from {} (height: {})",
                config.id,
                state_file.display(),
                state.consensus_state().height
            ),
            // Worth shouting about: the signer has no record of anything it
            // previously signed, so a validator replaying old heights will be
            // signed for again
            state::LoadOutcome::CreatedFresh => warn!(
                "[{}] no state file found: created {} at height 0, so double signing protection has no history",
                config.id,
                state_file.display()
            ),
        }

        if let Some(ref hook) = config.state_hook {
            // Applying the hook output can fail too (e.g. a block height beyond
            // the sanity limit), so both failures share the fail-closed policy
            let hook_result = state::hook::run(hook).and_then(|hook_output| {
                state
                    .update_from_hook_output(hook_output)
                    .map_err(|e| format_err!(ErrorKind::HookError, "{}", e).into())
            });

            if let Err(e) = hook_result {
                if hook.fail_closed {
                    return Err(e);
                } else {
                    // fail open: note the error to the log and proceed anyway
                    error!("error invoking state hook for chain {}: {}", config.id, e);
                }
            }
        }

        Ok(Self {
            id: config.id.clone(),
            sign_extensions: config.sign_extensions,
            keyring: KeyRing::new(config.key_format.clone()),
            state: Mutex::new(state),
        })
    }
}

/// Resolve the path of a chain's state file to an absolute path.
///
/// The default path is relative, so without resolving it the file a signer uses
/// depends on the working directory it was started from. Logging the absolute
/// path makes that visible instead of silently using a different file.
fn resolve_state_file_path(state_file: Option<&Path>, chain_id: &Id) -> Result<PathBuf, Error> {
    let path = match state_file {
        Some(path) => path.to_owned(),
        None => PathBuf::from(&format!("{chain_id}_priv_validator_state.json")),
    };

    path::absolute(&path).map_err(|e| {
        format_err!(
            ErrorKind::IoError,
            "couldn't resolve state file path `{}`: {}",
            path.display(),
            e
        )
        .into()
    })
}

/// Ensure no two chains are configured to share a state file.
///
/// Each chain keeps its own in-memory state and rewrites the whole file, so a
/// shared path means the chains silently clobber each other's last-signed
/// height. After a restart a chain can then load a lower height than it already
/// signed at and sign those heights again, which is slashable.
fn check_state_files_are_unique(configs: &[ChainConfig]) -> Result<(), Error> {
    let mut seen: Vec<(PathBuf, &Id)> = Vec::with_capacity(configs.len());

    for config in configs {
        let path = resolve_state_file_path(config.state_file.as_deref(), &config.id)?;

        if let Some((_, first)) = seen.iter().find(|(seen_path, _)| *seen_path == path) {
            fail!(
                ErrorKind::ConfigError,
                "chains `{}` and `{}` are both configured to use the state file `{}`:                  each chain requires its own",
                first,
                config.id,
                path.display()
            );
        }

        seen.push((path, &config.id));
    }

    Ok(())
}

/// Initialize the chain registry from the configuration file
pub fn load_config(config: &KmsConfig) -> Result<(), Error> {
    check_state_files_are_unique(&config.chain)?;

    for config in &config.chain {
        if let Some(warning) = config.key_format.misleading_gno_prefix_warning() {
            warn!("[{}] {}", config.id, warning);
        }

        REGISTRY.register(Chain::from_config(config)?)?;
    }

    let mut registry = REGISTRY.0.write().unwrap();
    keyring::load_config(&mut registry, &config.providers)
}

#[cfg(test)]
mod tests {
    use super::{Id, check_state_files_are_unique, resolve_state_file_path};
    use crate::config::chain::ChainConfig;
    use std::path::{Path, PathBuf};

    fn chain_config(id: &str, state_file: Option<&str>) -> ChainConfig {
        let state_file = match state_file {
            Some(path) => format!(r#","state_file":"{path}""#),
            None => String::new(),
        };

        serde_json::from_str(&format!(
            r#"{{"id":"{id}","key_format":{{"type":"bech32","account_key_prefix":"cosmospub","consensus_key_prefix":"cosmosvalconspub"}}{state_file}}}"#
        ))
        .unwrap()
    }

    #[test]
    fn distinct_state_files_are_accepted() {
        let configs = [
            chain_config("chain-a", Some("/var/lib/tmkms/a.json")),
            chain_config("chain-b", Some("/var/lib/tmkms/b.json")),
        ];

        check_state_files_are_unique(&configs).unwrap();
    }

    #[test]
    fn default_state_file_paths_do_not_collide() {
        let configs = [chain_config("chain-a", None), chain_config("chain-b", None)];

        check_state_files_are_unique(&configs).unwrap();
    }

    #[test]
    fn a_shared_state_file_is_rejected() {
        let configs = [
            chain_config("chain-a", Some("/var/lib/tmkms/shared.json")),
            chain_config("chain-b", Some("/var/lib/tmkms/shared.json")),
        ];

        check_state_files_are_unique(&configs)
            .expect_err("two chains sharing a state file must be rejected");
    }

    #[test]
    fn paths_that_resolve_to_the_same_file_are_rejected() {
        let configs = [
            chain_config("chain-a", Some("/var/lib/tmkms/shared.json")),
            chain_config("chain-b", Some("/var/lib/tmkms/./shared.json")),
        ];

        check_state_files_are_unique(&configs)
            .expect_err("equivalent paths must be treated as a collision");
    }

    #[test]
    fn default_state_file_path_is_absolute_and_names_the_chain() {
        let chain_id: Id = "test-chain".parse().unwrap();

        let path = resolve_state_file_path(None, &chain_id).unwrap();

        assert!(path.is_absolute(), "{} should be absolute", path.display());
        assert_eq!(
            path.file_name().unwrap(),
            "test-chain_priv_validator_state.json"
        );
    }

    #[test]
    fn relative_configured_path_is_resolved_against_the_working_directory() {
        let chain_id: Id = "test-chain".parse().unwrap();

        let path = resolve_state_file_path(Some(Path::new("state/chain.json")), &chain_id).unwrap();

        assert_eq!(
            path,
            std::env::current_dir().unwrap().join("state/chain.json")
        );
    }

    #[test]
    fn absolute_configured_path_is_left_alone() {
        let chain_id: Id = "test-chain".parse().unwrap();

        let path = resolve_state_file_path(Some(Path::new("/var/lib/tmkms/state.json")), &chain_id)
            .unwrap();

        assert_eq!(path, PathBuf::from("/var/lib/tmkms/state.json"));
    }
}
