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

# ProofHub Parachain Overview

This document describes the ProofHub components, capabilities

## Components

- Pallet: on-chain privacy logic (unsigned proof submission, deposits, fee pool, Merkle anchoring)
  - Path: pallets/proofs/src/lib.rs
- Verifier: no_std cryptographic verification (Schnorr balance, Bulletproofs range, Pedersen checks)
  - Path: verifier/src/lib.rs
- Runtime wiring: constants, accounts, limits, and pallet configuration
  - Path: runtime/src/configs/mod.rs

## Capabilities

- Schnorr balance proof
  - Checks s·H = R + c·agg bound via Merlin transcript.
  - Aggregates commitments: inputs − outputs − fee.
- Bulletproofs range proof
  - Verifies aggregated outputs + fee with deterministic transcript binding.
  - Deterministic padding to power-of-two party capacity.
- Pedersen deposit check
  - Validates commitment opening for public deposits: commitment = value*G + r*H.
- Merkle anchoring & state
  - Maintains CurrentRoot, RecentRoots window, Leaves, CommitmentIndex.
  - Enforces membership via merkle path or index-gate against an anchor root.
- Nullifiers & fee pool
  - NullifierUsed and FeeNullifierUsed prevent double-spends.
  - deposit_fee creates fee credits; submit_proof consumes and pays a base fee to block author.
- Events
  - ProofAccepted, ProofRejected, RangeProofVerified, FeeDeposited, FeePaid/FeePayoutFailed, DepositAccepted.

## Extrinsics (API)

- submit_proof(origin = none, proof: Vec<u8>, range_proof: BoundedVec<u8>, public_inputs: Vec<u8>, hints_blob: BoundedVec<u8>)
  - Privacy call (unsigned). Verifies range proof, Schnorr balance, membership, nullifiers; rotates roots; consumes fee credit and pays base fee.
- deposit_public(origin = signed, commitment: [u8;32], amount: u128, blinding: [u8;32], hints_blob: BoundedVec<u8>)
  - Verifies Pedersen opening; transfers funds to pool; appends commitment; recomputes and rotates Merkle root.
- deposit_fee(origin = signed, fee_commitment: [u8;32])
  - Transfers base fee to Paymaster account; records a fee commitment credit.

## Public Inputs

SCALE-encoded struct passed to the verifier:

- merkle_root: [u8;32]
- new_merkle_root: [u8;32] (or zero to compute on chain)
- input_commitments: Vec<[u8;32]>
- input_indices: Vec<u32>
- input_paths: Vec<Vec<[u8;32]>>
- nullifiers: Vec<[u8;32]>
- new_commitments: Vec<[u8;32]>
- fee_commitment: [u8;32]
- fee_nullifier: [u8;32]
- tx_id: [u8;16]

## Runtime Configuration

- Verifier hook: RuntimeProofVerifier delegates to verifier crate.
- Accounts & constants:
  - PaymasterPalletId → Paymaster fee account
  - PoolPalletId → Privacy pool account
  - PrivateBaseFee → fixed base fee paid per accepted proof
  - GenesisCommitments → optional faucet commitments (default empty)
- Limits:
  - MaxProofSize, MaxRangeProofSize, MaxOutputs
- Author payout: fixed base fee split between burn and author.


## Inter-chain Integration (XCM)

Other parachains can submit proofs via XCM Transact calling submit_proof, deposit_fee, or deposit_public on ProofHub.

High-level flow:

1. RWA parachain constructs proof and public inputs off-chain.
2. Sends XCM to ProofHub with a Transact call for submit_proof.
3. ProofHub verifies, anchors new root, pays author, and emits events.

## Security & Operations

- Weights are placeholders; add benchmarks and replace stubs for production.
- Provide your faucet GenesisCommitments to enable genesis note flows.
- Consider external review/audit of cryptographic code paths before mainnet deployment.

