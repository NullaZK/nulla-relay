# ScanProof Runtime (homomorphic lane)

`spec_name = "proofhub-runtime"`, **spec_version 14** (Phase 10).

> The crate is named `scanproof-runtime` but keeps `spec_name = "proofhub-runtime"` for
> historical compatibility with previous deployments.

ScanProof is the **homomorphic** private parachain of the Nulla Network
(para-id `2002`). Every private operation is verified inside the runtime using:

- **Pedersen commitments** on the Ristretto group (`curve25519-dalek` 4)
- **GK17 one-of-many membership proofs** (logarithmic-size, no trusted setup)
- **Merlin** transcripts for Fiat–Shamir, BLAKE2 / SHA-256 for hashing

The runtime exposes one custom pallet:

- [`scanproof-pallet-proofs`](../pallets/proofs/README.md) — `deposit_coin`,
  `purchase_coin`, `withdraw_coin`, `purchase_access_coin`, plus the legacy
  `deposit_public` / `withdraw_private` / `purchase_rwa` compatibility paths and
  the RWA-marketplace admin / paywall calls.

Phase 10 dropped the on-wire fee fields from the verifier format; proofs built against
spec_version 13 or older are rejected.

Built on the standard Polkadot SDK FRAME stack; see
[FRAME docs](https://paritytech.github.io/polkadot-sdk/master/polkadot_sdk_docs/polkadot_sdk/frame_runtime/index.html).
