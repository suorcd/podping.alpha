# AGENTS.md

Instructions for AI coding agents operating in this repository.

## Project Overview

Podping.alpha is a decentralized podcast feed notification system. It consists of
five independent Rust crates (no Cargo workspace). Each has its own `Cargo.toml`
and `Cargo.lock`.

| Crate | Path | Purpose |
|---|---|---|
| `gossip-listener` | `gossip-listener/` | Iroh gossip subscriber; receives and verifies notifications |
| `gossip-writer` | `gossip-writer/` | ZMQ-to-Iroh bridge; broadcasts notifications to the gossip network |
| `podping` | `podping/` | HTTP front-end; queues feed URLs via ZMQ |
| `dbif` | `podping/dbif/` | SQLite database interface library (used by `podping`) |
| `stresser` | `stresser/` | HTTP load testing tool |

## Build Commands

There is no Cargo workspace. Always specify the crate you are building.

```sh
# Build a single crate (debug)
cargo build --manifest-path gossip-listener/Cargo.toml

# Build a single crate (release)
cargo build --release --manifest-path gossip-listener/Cargo.toml

# Build all crates (debug)
./build.sh

# Build all crates (release)
./build.sh release

# Build gossip-listener via Nix (release, reproducible)
nix build .#gossip-listener
```

### System Dependencies

`podping` and `gossip-writer` require native libraries at build time:
- `capnproto` (Cap'n Proto compiler, used by `build.rs`)
- `libzmq3-dev` (ZeroMQ)
- `sqlite3` / `libsqlite3-dev`
- `openssl` / `libssl-dev`

`gossip-listener` and `stresser` have no native build dependencies beyond the
Rust toolchain. The Nix flake provides `openssl` and `pkg-config` automatically.

## Lint / Check

```sh
# Type-check a single crate without producing a binary
cargo check --manifest-path gossip-listener/Cargo.toml

# Clippy (no config file exists; use defaults)
cargo clippy --manifest-path gossip-listener/Cargo.toml

# Format check (no rustfmt.toml exists; use defaults)
cargo fmt --manifest-path gossip-listener/Cargo.toml -- --check
```

## Tests

**There are no tests in this repository.** No `#[test]` blocks, no `tests/`
directories, no `[dev-dependencies]`, and no CI pipeline exist. If you add tests:

```sh
# Run all tests for a crate
cargo test --manifest-path gossip-listener/Cargo.toml

# Run a single test by name
cargo test --manifest-path gossip-listener/Cargo.toml -- test_name

# Run tests matching a pattern
cargo test --manifest-path gossip-listener/Cargo.toml -- test_pattern
```

## Code Style Guidelines

### Rust Edition and Toolchain

All crates use **edition 2021**. No `rust-toolchain.toml` exists; the Nix flake
pins stable latest. No `rustfmt.toml` or `clippy.toml` exists.

### Imports

Group imports roughly in this order (matching the gossip-* crates):
1. `std::*`
2. External crates
3. Internal modules / `crate::` imports

No blank lines between groups. No enforced alphabetical sorting within groups.

```rust
use std::collections::HashSet;
use std::env;
use std::sync::Arc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use iroh::protocol::Router;
use serde::{Deserialize, Serialize};
```

### Formatting

- 4-space indentation (no tabs).
- K&R brace placement (opening brace on same line).
- No hard line length limit; long lines are tolerated.
- Trailing commas in struct literals.

### Naming Conventions

- **Functions / variables:** `snake_case`
- **Structs / enums / traits:** `PascalCase`
- **Constants:** `SCREAMING_SNAKE_CASE`
- **Enum variants:** `PascalCase`
- **Clones for spawned tasks:** use a descriptive prefix matching the task, e.g.
  `watchdog_sender`, `endorse_trusted`, `announce_node_id`.
- **Unused bindings that must be kept alive:** prefix with `_`, e.g.
  `let _router = Router::builder(...)...;`

### Error Handling

- **Binary entry points:** use `anyhow::Result<()>` (gossip-listener) or
  `Result<(), Box<dyn std::error::Error>>` (gossip-writer, stresser).
- **`?` operator:** preferred in the gossip-* crates. Use it for propagation.
- **`unwrap()`:** used freely for infallible operations (time, serialization of
  known-good data). Acceptable for `SystemTime::now().duration_since(UNIX_EPOCH)`.
- **`expect("reason")`:** use when an unwrap is justified but non-obvious.
  Always include a message explaining why it cannot fail.
- **Warn-and-continue:** `if let Err(e) = ... { eprintln!(...); }` for
  non-fatal errors in background tasks.
- **Signature verification:** returns `Result<bool, String>` where `Ok(false)`
  means unsigned and `Err(...)` means invalid.

### Comments

- **Section separators:** `//Section Name ---...---` (dashes to ~80-90 chars).
  Used to delimit major sections (Structs, Main, Functions).
- **Inline comments:** `//` with or without a space. No `///` doc comments are
  used in practice.
- **Subsections in gossip-writer:** `// --- Section Name ---` with triple dashes.

### Serialization (serde)

- Derive order: `Debug, Clone, Serialize, Deserialize`.
- Rename Rust keywords: `#[serde(rename = "type")]` on `msg_type` fields.
- Optional fields: `#[serde(default, skip_serializing_if = "Option::is_none")]`.
- **Canonical signing structs:** separate struct with borrowed fields in
  **alphabetical order by JSON key name**, derive only `Serialize`. Named
  `Canonical*` (e.g. `CanonicalNotification<'a>`, `CanonicalPeerEndorse<'a>`).

### Async Patterns

- Runtime: `#[tokio::main]` with `tokio` `full` feature.
- Fire-and-forget loops: `tokio::spawn(async move { loop { ... } })`.
- Blocking I/O: `tokio::task::spawn_blocking` (gossip-writer uses this for ZMQ).
- Shutdown: `tokio::signal::ctrl_c()` combined with `tokio::select!`.
- Channels: `tokio::sync::mpsc` to bridge blocking threads to async tasks.
  Use `tx.blocking_send()` from the blocking side.

### Logging

No logging framework is used. All output is `println!` / `eprintln!` with
hardcoded ANSI color codes and prefix tags:

```
[info]      general information
[error]     failures
[WARN]      non-fatal warnings (magenta \x1b[35m)
[ANNOUNCE]  peer announce messages (yellow \x1b[33m)
[ENDORSE]   peer endorse messages (green \x1b[32m)
[EVENT]     neighbor up/down (green/red)
[WATCHDOG]  re-bootstrap events (yellow \x1b[33m)
```

Always reset with `\x1b[0m` after colored output.

### Configuration

All runtime configuration uses environment variables with `env::var()`. Pattern
for string vars:

```rust
let value = env::var("VAR_NAME").unwrap_or_else(|_| DEFAULT.to_string());
```

Pattern for numeric vars:

```rust
let value: u64 = env::var("VAR_NAME")
    .ok()
    .and_then(|v| v.parse().ok())
    .unwrap_or(DEFAULT_VALUE);
```

### Known Duplication

`PeerAnnounce`, `GossipNotification`, `CanonicalNotification`, and several
helper functions (`load_known_peers`, `save_peer_if_new`, `load_or_create_node_key`,
`load_trusted_publishers`, `save_trusted_publishers`) are duplicated nearly
verbatim between `gossip-listener/src/main.rs` and `gossip-writer/src/main.rs`.
If extracting shared code, create a shared library crate.
