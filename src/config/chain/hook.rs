use serde::Deserialize;

/// Configuration for a particular hook to invoke
#[derive(Default, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct HookConfig {
    /// Command (with arguments) to invoke
    pub cmd: Vec<String>,

    /// Time limit (in seconds) for the command to exit and close its stdout (default 1)
    pub timeout_secs: Option<u64>,

    /// Whether or not to fail open or closed if this command fails to execute.
    /// Failing closed will prevent the KMS from starting if this command fails.
    pub fail_closed: bool,
}

#[cfg(test)]
mod tests {
    use super::HookConfig;

    #[test]
    fn deserializes_from_toml() {
        let config: HookConfig = toml::from_str(
            r#"
            cmd = ["/usr/bin/tmkms-state-hook", "--chain-id", "test-chain"]
            timeout_secs = 2
            fail_closed = true
        "#,
        )
        .expect("state_hook config should deserialize from TOML");

        assert_eq!(
            config.cmd,
            vec!["/usr/bin/tmkms-state-hook", "--chain-id", "test-chain"]
        );
        assert_eq!(config.timeout_secs, Some(2));
        assert!(config.fail_closed);
    }
}
