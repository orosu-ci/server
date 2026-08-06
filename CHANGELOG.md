# Changelog

All notable changes to the `api/` workspace (`orosu` lib, `orosu-server`, `orosu-keygen`) are documented
here. Versions are shared across all three crates (`[workspace.package] version` in `Cargo.toml`).

## 0.7.0 — 2026-08-06

A hardening release: no new features, no config or CLI changes, no wire-protocol changes. Every change
here fixes a finding from a full-scale code review of the workspace, conducted 2026-08-05 and tracked in
detail (failure scenarios, exact fixes, and regression tests) in
[`docs/code-review-2026-08-05.md`](docs/code-review-2026-08-05.md). 16 of 17 findings are fixed; the one
remaining (IP allow/deny lists trusting `X-Forwarded-For` unconditionally) is a structural
trusted-proxy design question, left open pending a decision on the right approach.

Existing deployments upgrade with zero required changes — every fix here is either strictly internal
behavior or a new safety rail that only activates on previously-mishandled input.

### Security

- **Zip-slip path traversal in attachment extraction (Critical).** A malicious zip attachment with an
  entry named e.g. `../../etc/cron.d/pwn` could write outside the intended extraction directory using
  the server process's own privileges. Entry names are now validated with `ZipFile::enclosed_name()`
  before use.
- **Zip-bomb attachments unbounded (Medium).** A small, highly-compressed attachment (or one with an
  enormous number of tiny entries) could exhaust server disk during extraction. Entry count and total
  decompressed size are now capped.
- **Non-contributory ECDH shared secrets accepted (Medium).** The protocol-v2 encryption handshake didn't
  check for a low-order-point attack on the X25519 exchange (defense-in-depth; not exploitable end-to-end
  as originally shipped, since the client independently detects the mismatch — see the review doc for
  the full analysis).
- **Generated private key files world-readable.** `orosu-keygen` now writes private keys with `0600`
  permissions regardless of umask; public keys remain unrestricted since they're meant to be shared.
- **`ClientKey` no longer derives `Debug`,** matching every other secret-holding type in the crate, so a
  future `{:?}` on a client's signing key fails to compile instead of risking a log leak.
- **`orosu-keygen` now warns on stderr** before printing a private key to stdout when no
  `--private-key-output` was given — the default behavior (print to stdout) is unchanged, since every
  documented workflow already passes the flag explicitly.

### Robustness

- **`listen: {socket: ...}` (Unix domain socket support) was completely non-functional** — every request
  500'd, because IP allow/deny-list middleware unconditionally required a `ConnectInfo<SocketAddr>`
  extension only ever populated for TCP connections. Also fixed: stale socket files from an unclean
  shutdown are now removed before rebinding.
- **`run_as` privilege dropping silently no-op'd on non-Linux Unix** (macOS, BSD) due to an overly narrow
  `cfg(target_os = "linux")` gate; widened to `cfg(unix)`, matching the actual platform support of the
  underlying APIs.
- **No timeout on the initial launch message or file-chunk uploads** — a client that never sent one, or
  stalled mid-upload, could tie up a connection indefinitely. Both now have bounded timeouts (10s / 30s).
- **Malformed attachment bytes panicked** instead of failing cleanly — non-zip garbage or a corrupted zip
  now produces the same clean rejection as every other malformed-input path, instead of unwinding the
  connection's task.
- **A `tokio::select!` race could silently drop a fast-exiting script's final output lines** when the
  task's exit and its last buffered output became ready on the same poll. Any output still buffered once
  the task handle resolves is now drained and forwarded before the exit code.
- **WebSocket `Ping`/`Pong` keepalives were treated as fatal malformed input** during the launch handshake
  or mid-upload, disconnecting otherwise-compliant peers or intermediaries. Now transparently tolerated,
  without reopening the timeout budget those keepalives could otherwise be used to extend.
- **Duplicate client or script names in `config.yaml` silently shadowed** the first match (via `.find()`)
  instead of being rejected — a copy-pasted client block with an unchanged `name:` now fails to start
  instead of silently making the second entry unreachable.
- **`--private-key-output`/`--public-key-output` pointing at the same path** silently overwrote the
  private key file with the public key; now rejected up front, before either file is generated.

### Chores

- Removed dead, unused attachment-archiving code (`AttachedFiles`, `FileChunkResult`, and friends —
  zero production callers since the JS action became the live client implementation) and its now-unused
  `glob` dependency.
- Fixed a stale code comment referencing a discontinued Rust CLI client as if it were still live.

## 0.6.0 — 2026-08-05

- Added end-to-end encryption (protocol version 2): an X25519 + HKDF-SHA256 + ChaCha20-Poly1305 handshake
  layered beneath the existing WebSocket connection, so script arguments, uploaded files, and streamed
  output stay confidential even if TLS is terminated at a reverse proxy in front of `orosu-server`.
  Opt-in and additive on both ends independently — see `README.md` for setup.
- `orosu-keygen --kind server` generates the new server identity key this feature needs.
