# pallet-proofhub-proofs (ProofHub — quantum lane, Phase 9)

Quantum-resistant private lane for the Nulla Network.
Built on STARK membership proofs (winterfell 0.13) + ML-DSA-44 signatures (FIPS 204) + BLAKE3 note hashing.

## What it does on-chain

The pallet performs **real cryptographic verification inside the runtime**:

- STARK verifier (`DepositV2Air`, `WithdrawV2Air`, `PurchaseRwaV2Air`) for proof of membership in the note Merkle tree
- ML-DSA-44 signature check (post-quantum) on the spending key
- BLAKE3 leaf hash: `NoteHash(amount, blinding, pkd)`
- Nullifier set to prevent double-spend
- Public balance ↔ pool transitions through XCM

## Extrinsics (Phase 9 — spec_version 127)

Phase 9 introduced **v2 zk-membership** dispatchables; the v1 legacy ones are kept for ABI
compatibility but **rejected at runtime** (`legacy deposits disabled`).

### Active (v2)

| Call | Origin | Purpose |
|---|---|---|
| `deposit_v2(leaf, amount, deposit_proof, hints_blob)` | signed | Public NULLA → private note (STARK `DepositV2Air`) |
| `withdraw_v2(auth, public_inputs, spend_proof)` | none (unsigned) | Private note → public NULLA. `public_inputs = WithdrawPublicV2 { merkle_root, nullifier, amount, destination: [u8; 32], tx_id }` |
| `purchase_rwa_v2(auth, public_inputs, spend_proof)` | none (unsigned) | Private purchase of an RWA listing. `public_inputs = SpendPublicV2 { ... }` |
| `purchase_access_v2(...)` | none (unsigned) | Private paywall purchase backed by a v2 spend proof |

`auth` is the ML-DSA-44 signature blob, `spend_proof` is the serialized STARK proof.

### Legacy (v1 — disabled in Phase 9)

`deposit_public`, `purchase_rwa`, `withdraw_private`, `purchase_access`
— kept in the Call enum for storage migrations, return `LegacyDisabled` at runtime.

### Marketplace / admin

`relist_private`, `set_rwa_price`, `set_access_config`

## Storage highlights

- `Notes`, `NoteRoots`, `NullifierUsed`
- `RwaListings`, `RwaPrice`, `AccessConfig`

## Wiring

`Proofs = pallet_proofhub_proofs` in `runtime/src/configs/mod.rs`.
Verifier crate: `proofhub-verifier` (winterfell 0.13 + fips204 0.4 + blake3 1.5).
