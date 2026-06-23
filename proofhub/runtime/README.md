# ProofHub Runtime (quantum lane)

`spec_name = "proofhub-runtime"`, **spec_version 127** (Phase 9).

ProofHub is the **quantum-resistant** private parachain of the Nulla Network
(para-id `2000`). It backs every private operation with on-chain verification of:

- **STARK membership proofs** (winterfell 0.13) over the note Merkle tree
- **ML-DSA-44 post-quantum signatures** (FIPS 204 via `fips204` 0.4)
- **BLAKE3** leaf hashing for note commitments

Phase 9 introduced the **v2 zk-membership** dispatchables and disabled the legacy v1 ones:

- `deposit_v2`
- `withdraw_v2`
- `purchase_rwa_v2`
- `purchase_access_v2`

See [`pallet-proofhub-proofs`](../pallets/proofs/README.md) for the full call list,
public-input layout (`WithdrawPublicV2`, `SpendPublicV2`) and storage maps.

XCM configuration anchors the network on the Westend genesis hash
(`RelayNetwork = ByGenesis(WESTEND_GENESIS_HASH)`); cross-chain transfers go through
the dedicated `transfer_assets_using_type_and_then` path because the relay enforces
the Asset Hub Migration guard on plain reserve transfers.

Built on the standard Polkadot SDK FRAME stack; see
[FRAME docs](https://paritytech.github.io/polkadot-sdk/master/polkadot_sdk_docs/polkadot_sdk/frame_runtime/index.html).
