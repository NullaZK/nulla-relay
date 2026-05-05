# pallet-proofs (ProofHub MVP)

Minimal pallet to:
- Store a `commitment: H256` plus opaque `payload: Vec<u8>` per submission
- Emit `ProofSubmitted` and allow marking/merkle-checking as verified

What it does NOT do (by design in this MVP):
- On-chain cryptographic verification of Pedersen commitments or homomorphic proofs
- Bulletproofs/zk verification inside the runtime (too heavy for WASM and gasless)

Recommended usage for now:
- Verify proofs off-chain, then call `verify_proof(commitment)` or `verify_merkle_proof(...)` to attest on-chain
- Use `payload` to carry proof bytes or a reference (hash/URI); the pallet treats it opaquely

API
- `submit_proof(origin, commitment: H256, payload: Vec<u8>)`
- `verify_proof(origin, commitment: H256)` (placeholder: flips `verified = true`)
- `verify_merkle_proof(origin, commitment: H256, leaf: Vec<u8>, siblings: Vec<H256>, dirs: Vec<bool>)`

Roadmap (if on-chain Pedersen is required):
- Add a compact commitment type (compressed group element bytes)
- Provide light-weight relations (e.g., sum of commitments) if feasible
- Keep heavy crypto (zk/SNARK/Bulletproof) verification off-chain or via a dedicated verifier chain/precompile

See wiring in the template runtime at `Proofs = pallet_proofs` and configuration in `runtime/src/configs/mod.rs`.
