# Nulla Relay CLI (First Upload)

This is the first public upload of the Nulla relay CLI (`nulla-relay`). It provides a branded command-line interface for running a local Nulla relay node, exporting chainspecs, and basic node operations.

Status
- Initial drop of the CLI only; additional components (service wrappers, packaging, parachain tooling) will follow.
- Builds inside the Polkadot SDK workspace and reuses the existing node service and Nulla runtime.
- Future updates will expand features and this README will be updated accordingly.

Requirements
- Rust toolchain (stable)
- This repository checked out with workspace dependencies (Polkadot SDK, Substrate)

Build
```bash
# From workspace root
cargo build -p nulla-cli --release

# Verify
./target/release/nulla-relay --help
```

Quick Start
- Export readable chainspec (defaults to `nulla-local`):
```bash
./target/release/nulla-relay build-spec --chain nulla-local > chainspec/nulla.json
```
- Export raw chainspec:
```bash
./target/release/nulla-relay build-spec --chain nulla-local --raw > chainspec/nulla-testnet.json
```
- Run a single local validator (force authoring):
```bash
./target/release/nulla-relay \
  --chain nulla-local \
  --base-path /tmp/nulla-you \
  --validator \
  --force-authoring
```

Notes
- This CLI is currently tied to the workspace node service/runtime and is not a standalone publishable crate yet.
- Protocol ID is `nulla`; properties include token symbol `NULLA`, decimals `12`, ss58 `42`.
- Base transaction fees are reduced for local/testnet usage; validator rewards include tips and inflation with a treasury share.

Roadmap
- Publish/reusable service layer (or pin SDK git dependencies for standalone builds).
- Chainspec tooling for custom validator/session keys at genesis.
- Parachain utilities and Proof Hub integration.
- Documentation updates here as features land.


# Nulla Relay: Runtime Sources (code only)

This archive contains the source code for the `nulla-relay` runtime (Relay Chain). It does not include any executables/binaries.

Uploaded to GitHub:
- CLI code (sources only)
- Runtime code (sources only)

Important:
- These components are NOT meant to be run as-is from the repository. To run a node you must build the full executable (release build) and run the produced binary.
- We will separately publish the official executable (binary) for operators who prefer not to compile locally.

What’s inside this archive
-  relay runtime sources (Cargo.toml, src/,  etc.)

Release notes
- The sources are shared for transparency and review. Production usage should rely on officially published binaries.

Support
For questions or issues, please open an issue in the GitHub repository where the CLI and Runtime sources are hosted.
