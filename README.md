# Nulla — Relay Chain & Privacy Parachains

Nulla is a Substrate-based privacy network for real-world assets, DeSci, AI agents, and autonomous economies. It runs two parallel privacy lanes — **ProofHub** (Quantum Lane) and **ScanProof** (Homomorphic Lane) — both settling private ownership commitments on the same **RWA Appchain**.

Neither lane is primary. They are peer implementations with independent cryptographic stacks, lane-local note domains, and the same settlement endpoint.

---

## Architecture Overview

```
+-------------------------+    +-------------------------+
|   ProofHub              |    |   ScanProof             |
|   Quantum Lane          |    |   Homomorphic Lane      |
|   BLAKE3 + ML-DSA-44    |    |   Pedersen + Schnorr    |
|                         |    |   + Bulletproofs        |
|   Lane-local notes      |    |   Lane-local notes      |
|   Lane-local nullifiers |    |   Lane-local nullifiers |
+------------+------------+    +------------+------------+
             |   XCM reserve-transfer        |
             +--------------+----------------+
                            v
             +------------------------------+
             |   RWA Appchain               |
             |   ownership_commitment       |
             |   settlement (para 2001)     |
             +------------------------------+
```

Users choose a lane at entry. Notes, Merkle trees, and nullifier sets are lane-local and not shared across lanes. Both lanes forward valid purchase authorizations to the RWA Appchain via XCM reserve-transfer.

---

## ProofHub — Quantum Lane

ProofHub is the Quantum Lane parachain. It uses hash-based and lattice-based primitives, making it resistant to quantum adversaries.

### Cryptographic Primitives

- **BLAKE3** — commitment scheme, spend-tag derivation, purchase message hashing
- **ML-DSA-44 (FIPS 204)** — spend-tag binding and purchase authorization signatures
- Lane-local BLAKE3 Merkle tree and nullifier set

### Commitment Scheme

```
C = BLAKE3("nulla_commitment_v1" || value_le64 || blinding_32)
spend_tag = BLAKE3("nulla_spend_tag_v1" || C || recipient_pk)
```

### Capabilities

- `deposit_private` — creates a lane-local BLAKE3 note
- `purchase_rwa` — verifies spend-tag and ML-DSA-44 signature, authorizes RWA purchase
- `relist_private` — re-enters a commitment into the note pool after relisting
- `withdraw_private` — burns note, withdraws to public balance
- `redeem_rwa_ownership` — redeems ownership commitment on the RWA Appchain

### XCM Settlement Flow

1. ProofHub verifies lane-local proof (spend-tag, ML-DSA-44, nullifier, Merkle path).
2. Emits XCM reserve-transfer to RWA Appchain (para 2001) with `ownership_commitment` update.
3. RWA Appchain anchors the new ownership state.

---

## ScanProof — Homomorphic Lane

ScanProof (`scanproof-runtime`) is the Homomorphic Lane parachain (para ID 2002, RPC port 9957). It uses additive homomorphic commitments over Ristretto255, enabling private value composition without revealing amounts.

**Status:** public testnet. Deployed on Nulla relay. Production release pending collator onboarding.

### Cryptographic Primitives

- **Pedersen commitments (Ristretto255)** — `C = value*G + blinding*H`; additive: `C(a) + C(b) = C(a+b)`
- **Schnorr balance proof** — checks `s*H = R + c*agg` via Merlin transcript; aggregates `inputs - outputs - fee`
- **Bulletproof range proofs** — verifies outputs + fee are in range; deterministic transcript binding
- **Blake2b-256 Merkle tree** — lane-local commitment anchoring
- Lane-local nullifier sets (`NullifierUsed`, `FeeNullifierUsed`)

### Components

- **Pallet** (`pallets/proofs/src/lib.rs`) — on-chain privacy logic: unsigned proof submission, deposits, fee pool, Merkle anchoring
- **Verifier** (`verifier/src/lib.rs`) — `no_std` cryptographic verification: Schnorr balance, Bulletproofs range, Pedersen checks
- **Runtime wiring** (`runtime/src/configs/mod.rs`) — constants, accounts, limits, pallet configuration

### Extrinsics (API)

- `submit_proof(origin = none, proof, range_proof, public_inputs, hints_blob)` — unsigned privacy call; verifies range proof, Schnorr balance, membership, nullifiers; rotates roots; pays base fee to block author
- `deposit_public(origin = signed, commitment, amount, blinding, hints_blob)` — verifies Pedersen opening; transfers to pool; appends commitment; rotates Merkle root
- `deposit_fee(origin = signed, fee_commitment)` — transfers base fee to Paymaster; records fee credit

### Public Inputs (SCALE-encoded)

- `merkle_root: [u8;32]`
- `new_merkle_root: [u8;32]` (or zero to compute on-chain)
- `input_commitments: Vec<[u8;32]>`
- `input_indices: Vec<u32>`
- `input_paths: Vec<Vec<[u8;32]>>`
- `nullifiers: Vec<[u8;32]>`
- `new_commitments: Vec<[u8;32]>`
- `fee_commitment: [u8;32]`
- `fee_nullifier: [u8;32]`
- `tx_id: [u8;16]`

### Runtime Configuration

- `RuntimeProofVerifier` delegates to the verifier crate
- `PaymasterPalletId` — Paymaster fee account
- `PoolPalletId` — Privacy pool account
- `PrivateBaseFee` — fixed base fee per accepted proof; split between burn and block author
- `GenesisCommitments` — optional faucet commitments (default empty)
- Limits: `MaxProofSize`, `MaxRangeProofSize`, `MaxOutputs`

### XCM Settlement Flow

1. ScanProof verifies lane-local proof (Schnorr balance, Bulletproof range, Merkle path, nullifiers).
2. Emits XCM reserve-transfer to RWA Appchain (para 2001) with `ownership_commitment` update.
3. RWA Appchain anchors the new ownership state.


