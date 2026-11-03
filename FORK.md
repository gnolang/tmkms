# tmkms — Fork Changes

This is a hardened fork of [iqlusioninc/tmkms](https://github.com/iqlusioninc/tmkms),
branched from upstream `main` at [`de2b155`](https://github.com/iqlusioninc/tmkms/commit/de2b15536ed636a71f37303ef6189e889fe66dca)
(version `0.15.0`), plus a round of security and correctness fixes driven by
multi-agent security reviews of the whole tree, and gno.land-specific additions.

It is published as a container image for gno.land validators:

```
ghcr.io/aeddi/tmkms:v0.16.0-gno.3
```

The fork is missing no upstream commits. Fixes are being prepared as individual
upstream PRs; every branch behind the changes below is preserved on this fork for
that purpose. Entries marked as a gno.land addition stay here, since upstream
serves no gno.land chain.

> **Upgrading from upstream 0.15.0 is not a no-op.** Several fixes are secure by
> default and will refuse to start on a configuration upstream accepted. Read
> [Behaviour changes](#behaviour-changes-read-before-upgrading) before rolling out.

## Summary

Severity reflects impact on a validator: key compromise > equivocation/slashing >
liveness/DoS > hygiene.

| #   | Change                                                                        | Severity   | Kind                |
| --- | ----------------------------------------------------------------------------- | ---------- | ------------------- |
| 1   | Double-sign state is written durably (fsync of file + parent directory)       | **High**   | Upstream bug        |
| 2   | Two chains sharing one `state_file` is now a startup error                    | **High**   | Novel upstream fix  |
| 3   | Secret files get `0600` even when the file already exists                     | **High**   | Upstream bug        |
| 4   | `Debug` on the Ed25519 signing key no longer prints the consensus seed         | **Medium** | Upstream bug        |
| 5   | `state_hook` works at all, persists its height, and honours `fail_closed`     | **Medium** | Upstream bug (dead) |
| 6   | A freshly created state file is warned about; its path is logged absolute      | **Medium** | Upstream bug        |
| 7   | State is persisted before the in-memory guard advances                        | **Medium** | Hardening           |
| 8   | Validator peer-ID verification is required unless explicitly disabled          | **Medium** | Hardening           |
| 9   | Committed Fortanix DSM API key removed from templates and docs                 | **Medium** | Credential exposure |
| 10  | Panics reachable from valid input replaced with errors                        | **Medium** | Liveness            |
| 11  | `tmkms init` will not destroy an existing identity key without `-f`            | **Medium** | Data loss           |
| 12  | Disk failures are no longer reported as "attempted double sign"                | **Low**    | Observability       |
| 13  | Bounded TCP connect, Unix-socket timeouts, no peer payloads in logs            | **Low**    | Liveness/DoS        |
| 14  | Zeroization gaps closed in key load, keygen and `yubihsm keys import`          | **Low**    | Hygiene             |
| 15  | Dependencies refreshed, CI hardened, dev image off EOL centos:7                | **Low**    | Supply chain        |
| 16  | `tmkms ledger init` can succeed at all, and honours the double-sign check      | **Low**    | Upstream bug (dead) |
| 17  | A `gno` key format prints the public key gno.land accepts                      | **Low**    | gno.land addition   |

## Behaviour changes (read before upgrading)

Each of these is deliberate. Everything not listed here behaves as upstream 0.15.0.

- **A `tcp://` validator address must carry an `@peer_id` prefix.** Without one the
  validator cannot be authenticated, so tmkms now refuses to start rather than
  warning. Set `allow_unverified_peer = true` on the `[[validator]]` block to keep
  the old behaviour.
- **The state file's directory must be readable by the tmkms user and support
  `fsync` on a directory handle.** Where it does not, signing fails closed rather
  than proceeding without durable double-sign protection.
- **Two `[[chain]]` blocks may not share a `state_file`** — this is now a startup
  error naming both chains.
- **`tmkms init` refuses to overwrite** an existing `tmkms.toml` or identity key
  unless `-f`/`--force` is passed (the flag its usage text already advertised).
- **`tmkms ledger init` requires `-H`/`--height` and `-r`/`--round`**, and rejects a
  round outside `i32` instead of silently truncating it.
- **`tmkms yubihsm detect` no longer accepts `-c`/`--config`.** That flag was
  silently ignored; passing it is now an error rather than a false impression.
- **Config errors are fatal at startup** instead of being retried forever.
- **`state_hook` requires an explicit `fail_closed`**, and now actually runs (see #5).
- New warnings, not errors: key files readable by group or others, a freshly
  created state file with no signing history, and gno.land's `gpub` Bech32 prefix
  wherever it is applied — a `bech32` `key_format`'s consensus prefix, or
  `yubihsm keys generate -p` (see #17).

## Details

Only the changes whose reasoning is not obvious from the summary.

### 1. Durable double-sign state (High)

Upstream wrote the state file with a temp file plus `rename` and no `fsync` — neither
of the contents nor of the parent directory. The ordering was already correct
(persist before signing), but the persist was not durable: a crash or power loss in
the writeback window could revert the file to an older height/round/step, after which
the signer would sign a conflicting vote for a height it had already voted on.

Fixed with the standard atomic-and-durable replace: write, `fsync` the file, `rename`,
then `fsync` the parent directory. On macOS this issues `F_FULLFSYNC`, which is
required there for media durability. Reported upstream as
[gnolang/gno#5915](https://github.com/gnolang/gno/issues/5915).

Trade-off: the parent directory is opened and fsynced on every state write, so a
directory the tmkms user cannot read (or a filesystem that rejects directory fsync)
now fails closed where upstream kept signing.

### 2. Two chains sharing one state file (High)

Each chain keeps its own in-memory state and rewrites the whole file, and nothing
compared paths across chains. An operator copy-pasting a `[[chain]]` block and
leaving the same `state_file` got silent mutual clobbering: chain A writes height
100, chain B writes 50, and after a restart chain A loads 50 and re-signs heights it
has already voted on. Paths are now resolved to absolute and compared before any
chain is registered.

### 5. `state_hook` never worked in any release (Medium)

The feature that recovers the true block height after state-file loss was dead twice
over: `cmd` was typed `Vec<OsString>`, which serde cannot deserialize from a TOML
string, so any config containing a `state_hook` failed to load; and the child process
was spawned without piping stdout, so `run()` always took its own "couldn't consume
stdout" error path. The only test discarded its result with `let _ =`, which is why
this went unnoticed.

Additionally, a hook height beyond the 9000-block sanity limit only logged a warning,
so `fail_closed = true` could not stop startup against knowingly-stale state, and the
hook-derived height was never written to disk. All three are fixed, and the hook
subsystem now has real tests.

### 8. Peer-ID verification (Medium)

Upstream compared the validator's peer ID only when the config supplied one, and
merely warned when it did not — carrying a `TODO` that it should be mandatory. An
unauthenticated peer reaching the signer can drive the double-sign watermark forward
and deny signing for the real validator. Verification is now required, with
`allow_unverified_peer = true` as a documented escape hatch.

### 16. `tmkms ledger init` (Low)

The command built a `Vote` stamped with a *proposal* message code, which can never
convert: `vote::Type` accepts only prevote and precommit, and the conversion also
rejects the missing timestamp. Upstream ended that path in `.unwrap()`, so the
command panicked on every invocation. It now builds an actual `Proposal` and routes
the signature through the double-sign check.

The signing call itself still requires Ledger hardware and is therefore untested.

### 17. A `gno` key format (Low)

`key_format` only drives how tmkms displays a key, and none of its types printed
the string gno.land uses. With `{ type = "bech32", consensus_key_prefix = "gpub" }`
tmkms printed `gpub1zcjduepq…`, which looks like gno.land's key but is Bech32 over
the legacy Tendermint amino layout: gno.land's `crypto.PubKeyFromBech32` rejects it,
and the valoper realm panics on that error, so operators had to copy the key out of
`gnoland`'s start-up log instead.

`{ type = "gno" }` prints Bech32 `gpub` over the amino `Any` of the key — the string
`gnoland` logs for its validator and the valoper realm accepts. A `bech32`
`key_format` whose `consensus_key_prefix` is `gpub` warns once per chain, both at
start-up and in `tmkms yubihsm keys list`, pointing at the new format; so does
`tmkms yubihsm keys generate -p gpub`, which has no chain to take a format
from. Account keys
and non-Ed25519 keys fall back to hex: gno.land's validators sign with Ed25519
consensus keys, so no other key type has a gno encoding to print.

Wrapping the key in an amino `Any` makes the payload 55 bytes, which Bech32 expands
to 99 characters, past BIP-173's 90-character limit. A tool that enforces the limit
rejects a key gno.land itself accepts.

Signing is unaffected either way.

## Deliberately not changed

- **The validator-facing `RemoteSignerError` is unchanged.** Internally a persistence
  failure and an equivocation attempt are now distinct error kinds, but on the wire
  only a double sign returns a structured error; other state failures end the session.
  Both refuse to sign, so there is no safety difference, and an unavailable signer is
  a more honest signal for a disk fault than a per-request error the validator logs
  and moves past.
- **`RUSTSEC-2026-0009` (`time`) stays ignored** in `.cargo/audit.toml`. The fix
  requires Rust 1.88, above this crate's 1.85 MSRV, so the resolver holds `time`
  back. It is not reachable here: the advisory needs untrusted format descriptions,
  while the transitive users parse fixed formats. Revisit when the MSRV moves.
- **The container runs as root**, matching the previously published image, because
  key and state files arrive on a host-mounted volume whose ownership is managed
  outside the image.

## Verification

- `cargo fmt --all -- --check` and `cargo clippy --all-features` — clean.
- `cargo test --all-features -- --test-threads 1` — 63 unit + 20 integration tests
  pass (10 ignored, all hardware-dependent).
- The published image is pulled and checked on every release: it reports its own
  version, keeps `tmkms` as the entrypoint, and links the USB libraries the
  `yubihsm`/`ledger` backends need.
