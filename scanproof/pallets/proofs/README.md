# scanproof-pallet-proofs (ScanProof — homomorphic lane, Phase 10)

Homomorphic private lane for the Nulla Network.
Built on Pedersen commitments over Ristretto (curve25519-dalek 4) + GK17 one-of-many
membership proofs + Merlin transcripts.

## What it does on-chain

The pallet performs **real cryptographic verification inside the runtime**:

- Pedersen commitment math on Ristretto group
- GK17 one-of-many proof verification (logarithmic-size, no trusted setup)
- Serial-number set per group to prevent double-spend
- Storage map `CoinLocation: coin_serial → (group_id: u32, index: u32)`
- Public balance ↔ pool transitions through XCM

Sub-second proving on the client; verification cost stays well inside a single block.

## Extrinsics (Phase 10 — spec_version 14)

Phase 10 dropped the on-wire fee fields from the verifier format; proofs built against
spec_version 13 or older are rejected.

### Homomorphic coin lane (active)

| Call | Origin | Purpose |
|---|---|---|
| `deposit_coin(...)` | signed | Public NULLA → homomorphic coin in a one-of-many group |
| `withdraw_coin(group_id, serial, amount, destination, tx_id, oom_proof)` | none (unsigned) | Coin → public NULLA on a destination address |
| `purchase_coin(coin_idx, serial, oom_proof, listing_id, ...)` | none (unsigned) | Private purchase of an RWA listing paid with a coin |
| `purchase_access_coin(...)` | none (unsigned) | Private paywall purchase backed by a coin |

### Legacy compatibility (Phase 8 and earlier)

| Call | Purpose |
|---|---|
| `deposit_public(amount, commitment, ...)` | Single-shot Pedersen deposit (pre-coin lane) |
| `submit_proof(...)` | Generic proof submission used by old marketplace flows |
| `purchase_rwa(...)` | Legacy private RWA purchase |
| `withdraw_private(...)` | Legacy private withdraw |

### Marketplace / admin

`set_rwa_price`, `set_access_config`, `purchase_access`

## Wiring

`Proofs = scanproof_pallet_proofs` in `runtime/src/configs/mod.rs`.
Verifier crate: `scanproof-verifier` (curve25519-dalek 4 + merlin 3 + sha2 0.10 + blake2 0.10).
