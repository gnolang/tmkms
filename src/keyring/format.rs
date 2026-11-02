//! Chain-specific key configuration

use cometbft::CometbftKey;
use serde::{Deserialize, Serialize};
use subtle_encoding::{base64, bech32};

/// Protobuf [`Any`] type URL for Ed25519 public keys
const ED25519_TYPE_URL: &str = "/cosmos.crypto.ed25519.PubKey";

/// Protobuf [`Any`] type URL for secp256k1 public keys
const SECP256K1_TYPE_URL: &str = "/cosmos.crypto.secp256k1.PubKey";

/// Human-readable part of gno.land's Bech32 public keys
const GNO_PUBKEY_PREFIX: &str = "gpub";

/// Length of an Ed25519 public key in bytes
const ED25519_PUBKEY_LEN: usize = 32;

/// Amino `Any` prefix for a gno.land Ed25519 public key.
///
/// Protobuf field 1 carries the type URL `/tm.PubKeyEd25519`; field 2 opens a
/// 34-byte `PubKeyEd25519` message whose own field 1 carries the 32 raw key
/// bytes, which are appended to this prefix.
///
/// The three length bytes are derived from what follows them: `0x11` is the
/// length of the type URL, `0x22` the key plus its own two header bytes, and
/// `0x20` the key. Editing the type URL or the key size means editing them too;
/// `gno_amino_any_prefix_lengths_are_consistent` checks they agree.
const GNO_ED25519_ANY_PREFIX: &[u8] = b"\x0a\x11/tm.PubKeyEd25519\x12\x22\x0a\x20";

/// Options for how keys for this chain are represented
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type")]
pub enum Format {
    /// Use the Bech32 serialization format with the given key prefixes
    #[serde(rename = "bech32")]
    Bech32 {
        /// Prefix to use for Account keys
        account_key_prefix: String,

        /// Prefix to use for Consensus keys
        consensus_key_prefix: String,
    },

    /// JSON-encoded Cosmos protobuf representation of keys
    #[serde(rename = "cosmos-json")]
    CosmosJson,

    /// Hex is a baseline representation
    #[serde(rename = "hex")]
    Hex,

    /// gno.land's encoding: Bech32 `gpub` over the amino `Any` of the key.
    ///
    /// This is the string gnoland logs for its validator key and the one the
    /// valoper realm accepts. Only Ed25519 consensus keys have a gno encoding;
    /// account keys and other key types print as hex under this format.
    ///
    /// The result is 99 characters, past BIP-173's 90-character limit, because
    /// gno.land's encoding is: tools that enforce that limit reject the string
    /// even though gno.land accepts it.
    #[serde(rename = "gno")]
    Gno,
}

impl Format {
    /// Serialize a `CometbftKey` according to chain-specific rules
    pub fn serialize(&self, public_key: CometbftKey) -> String {
        match self {
            Format::Bech32 {
                account_key_prefix,
                consensus_key_prefix,
            } => match public_key {
                CometbftKey::AccountKey(pk) => {
                    bech32::encode(account_key_prefix, cometbft::account::Id::from(pk))
                }
                CometbftKey::ConsensusKey(pk) => pk.to_bech32(consensus_key_prefix),
            },
            Format::CosmosJson => {
                let pk = match public_key {
                    CometbftKey::AccountKey(pk) => PublicKeyJson::from(&pk),
                    CometbftKey::ConsensusKey(pk) => PublicKeyJson::from(&pk),
                };
                serde_json::to_string(&pk).expect("JSON serialization error")
            }
            Format::Hex => match public_key {
                CometbftKey::AccountKey(pk) => pk.to_hex(),
                CometbftKey::ConsensusKey(pk) => pk.to_hex(),
            },
            Format::Gno => match public_key {
                CometbftKey::ConsensusKey(pk @ cometbft::PublicKey::Ed25519(_)) => {
                    let mut any =
                        Vec::with_capacity(GNO_ED25519_ANY_PREFIX.len() + ED25519_PUBKEY_LEN);
                    any.extend_from_slice(GNO_ED25519_ANY_PREFIX);
                    any.extend_from_slice(&pk.to_bytes());
                    bech32::encode(GNO_PUBKEY_PREFIX, any)
                }
                // gno.land's validators sign with Ed25519 consensus keys; no
                // other key type has a gno encoding to print
                CometbftKey::AccountKey(pk) | CometbftKey::ConsensusKey(pk) => pk.to_hex(),
            },
        }
    }

    /// Warning to emit when this format prints something that resembles
    /// gno.land's encoding without being decodable as it.
    pub fn misleading_gno_prefix_warning(&self) -> Option<&'static str> {
        match self {
            Format::Bech32 {
                consensus_key_prefix,
                ..
            } if consensus_key_prefix == GNO_PUBKEY_PREFIX => Some(
                "key_format `bech32` with the `gpub` prefix prints Bech32 over the legacy \
                 Tendermint amino layout, which gno.land cannot decode; \
                 use `key_format = { type = \"gno\" }` to print the key gno.land accepts",
            ),
            _ => None,
        }
    }
}

/// Serde encoding type for JSON public keys.
///
/// Uses Protobuf JSON encoding conventions.
#[derive(Deserialize, Serialize)]
struct PublicKeyJson {
    /// `@type` field e.g. `/cosmos.crypto.ed25519.PubKey`.
    #[serde(rename = "@type")]
    type_url: String,

    /// Key data: standard Base64 encoded with padding.
    key: String,
}

impl From<&cometbft::PublicKey> for PublicKeyJson {
    fn from(public_key: &cometbft::PublicKey) -> PublicKeyJson {
        let type_url = match public_key {
            cometbft::PublicKey::Ed25519(_) => ED25519_TYPE_URL,
            cometbft::PublicKey::Secp256k1(_) => SECP256K1_TYPE_URL,
            // `cometbft::PublicKey` is `non_exhaustive`
            _ => unreachable!("unknown pubic key type"),
        }
        .to_owned();

        let key = String::from_utf8(base64::encode(public_key.to_bytes())).expect("UTF-8 error");
        PublicKeyJson { type_url, key }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cometbft::PublicKey;
    use subtle_encoding::hex;

    /// Ed25519 consensus key used for every vector here, as `tmkms` prints it
    /// under `key_format = { type = "hex" }`
    const EXAMPLE_KEY_HEX: &str =
        "59F22B8CC0B124EC2CD281858BFF7349B379B2E27C6E5557FEED3343F54089E9";

    /// `crypto.PubKeyToBech32` of `EXAMPLE_KEY_HEX` in gno.land: the string
    /// gnoland logs and the valoper realm accepts
    const EXAMPLE_GNO_KEY: &str = "gpub1pggj7ard9eg82cjtv4u52epjx56nzwgjyg9zqk0j9wxvpvfyaskd9qv930lhxjdn0xewylrw24tlamfng065pz0fqksh98";

    /// What `bech32` with gno.land's prefix prints: bech32 over the legacy
    /// Tendermint amino layout, which gno.land's decoder rejects
    const EXAMPLE_LEGACY_KEY: &str =
        "gpub1zcjduepqt8ezhrxqkyjwctxjsxzchlmnfxehnvhz03h924l7a5e58a2q385sfcnt2k";

    /// Compressed SEC1 encoding of the secp256k1 generator point
    const EXAMPLE_SECP256K1_KEY_HEX: &str =
        "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";

    fn example_key() -> PublicKey {
        let bytes = hex::decode_upper(EXAMPLE_KEY_HEX).unwrap();
        PublicKey::from_raw_ed25519(&bytes).unwrap()
    }

    fn gno_prefixed_bech32() -> Format {
        Format::Bech32 {
            account_key_prefix: "gpub".to_owned(),
            consensus_key_prefix: "gpub".to_owned(),
        }
    }

    /// The embedded length bytes have to agree with the type URL and key they
    /// describe, which a careless edit to either would break
    #[test]
    fn gno_amino_any_prefix_lengths_are_consistent() {
        const TYPE_URL: &str = "/tm.PubKeyEd25519";

        // Field 1: the type URL, preceded by its length
        assert_eq!(GNO_ED25519_ANY_PREFIX[0], 0x0a);
        assert_eq!(usize::from(GNO_ED25519_ANY_PREFIX[1]), TYPE_URL.len());
        assert_eq!(
            &GNO_ED25519_ANY_PREFIX[2..2 + TYPE_URL.len()],
            TYPE_URL.as_bytes()
        );

        // Field 2: a `PubKeyEd25519` holding the key, so the key plus the two
        // header bytes of its own field 1
        assert_eq!(GNO_ED25519_ANY_PREFIX[19], 0x12);
        assert_eq!(
            usize::from(GNO_ED25519_ANY_PREFIX[20]),
            ED25519_PUBKEY_LEN + 2
        );
        assert_eq!(GNO_ED25519_ANY_PREFIX[21], 0x0a);
        assert_eq!(usize::from(GNO_ED25519_ANY_PREFIX[22]), ED25519_PUBKEY_LEN);

        assert_eq!(GNO_ED25519_ANY_PREFIX.len(), 2 + TYPE_URL.len() + 4);
    }

    #[test]
    fn gno_format_serializes_an_ed25519_consensus_key_as_gno_does() {
        let serialized = Format::Gno.serialize(CometbftKey::ConsensusKey(example_key()));

        assert_eq!(serialized, EXAMPLE_GNO_KEY);
    }

    #[test]
    fn gno_format_falls_back_to_hex_for_account_keys() {
        let serialized = Format::Gno.serialize(CometbftKey::AccountKey(example_key()));

        assert_eq!(serialized, EXAMPLE_KEY_HEX);
    }

    /// `AccountKey(Ed25519)` is rejected before it reaches a format
    /// (`KeyRing::add_ed25519`), so the reachable fallback is a consensus key
    /// of another type
    #[test]
    fn gno_format_falls_back_to_hex_for_non_ed25519_consensus_keys() {
        let bytes = hex::decode_upper(EXAMPLE_SECP256K1_KEY_HEX).unwrap();
        let pk = PublicKey::from_raw_secp256k1(&bytes).unwrap();

        let serialized = Format::Gno.serialize(CometbftKey::ConsensusKey(pk));

        assert_eq!(serialized, EXAMPLE_SECP256K1_KEY_HEX);
    }

    #[test]
    fn gno_format_deserializes_from_its_tag() {
        let from_json: Format = serde_json::from_str(r#"{"type":"gno"}"#).unwrap();
        let from_toml: Format = toml::from_str(r#"type = "gno""#).unwrap();

        assert!(matches!(from_json, Format::Gno));
        assert!(matches!(from_toml, Format::Gno));
    }

    #[test]
    fn bech32_with_the_gno_prefix_warns() {
        assert!(
            gno_prefixed_bech32()
                .misleading_gno_prefix_warning()
                .is_some()
        );
    }

    /// Only the consensus prefix decides: the account prefix names a different
    /// encoding (`bech32` hashes account keys to an `account::Id`)
    #[test]
    fn only_the_consensus_prefix_triggers_the_warning() {
        let account_only = Format::Bech32 {
            account_key_prefix: "gpub".to_owned(),
            consensus_key_prefix: "cosmosvalconspub".to_owned(),
        };

        assert!(account_only.misleading_gno_prefix_warning().is_none());
        assert!(
            gno_prefixed_bech32()
                .misleading_gno_prefix_warning()
                .unwrap()
                .contains("gno.land cannot decode")
        );
    }

    #[test]
    fn other_formats_do_not_warn() {
        assert!(Format::Gno.misleading_gno_prefix_warning().is_none());
        assert!(Format::Hex.misleading_gno_prefix_warning().is_none());
        assert!(Format::CosmosJson.misleading_gno_prefix_warning().is_none());
        assert!(
            Format::Bech32 {
                account_key_prefix: "cosmospub".to_owned(),
                consensus_key_prefix: "cosmosvalconspub".to_owned(),
            }
            .misleading_gno_prefix_warning()
            .is_none()
        );
    }

    /// Pins the `bech32` output for gno.land's prefix, so the difference from
    /// the `gno` format stays visible.
    #[test]
    fn bech32_with_the_gno_prefix_prints_the_legacy_layout() {
        let serialized = gno_prefixed_bech32().serialize(CometbftKey::ConsensusKey(example_key()));

        assert_eq!(serialized, EXAMPLE_LEGACY_KEY);
    }
}
