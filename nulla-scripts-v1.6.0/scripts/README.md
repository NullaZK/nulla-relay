# Nulla Protocol — Deployment & Operations Scripts

Node.js scripts for deploying, upgrading, and auditing the Nulla testnet.

## Prerequisites

```bash
npm install @polkadot/api bn.js
```

All scripts connect to local WebSocket endpoints by default. Override with
environment variables where supported.

---

## Scripts

### upgrade_proofhub_runtime.js

Performs a live forkless runtime upgrade on the ProofHub parachain.

- Reads the compiled WASM from `target/release/wbuild/proofhub-runtime/`
- Submits `sudo.sudo(system.setCode)` signed by Alice
- Waits for finalization, then queries the new `spec_version`
- Exits with error if `spec_version != 109`

This script was used to deploy Phase 6 (spend_tag unlinkability) on the live
testnet. The upgrade is forkless — no chain restart required.

```bash
node scripts/upgrade_proofhub_runtime.js
# Connects to: ws://127.0.0.1:9947
```

---

### upgrade_rwa_runtime.js

Same as above but for the RWA parachain.

- Reads WASM from `target/release/wbuild/rwa-runtime/`
- Verifies `spec_version == 102` after upgrade
- Checks that `xcmRecordPurchase` and `redeemRwaOwnership` extrinsics are present

This script includes a bug fix from Phase 6: the version check was previously
inverted (`!= 101` instead of `!= 102`), causing false SUCCESS reports. The
fix is included in this version.

```bash
node scripts/upgrade_rwa_runtime.js
# Connects to: ws://127.0.0.1:9955
```

---

### audit_chain_state.js

Full on-chain state audit across both chains simultaneously.

Queries ProofHub (spec 109):
- `SpendTagValues` — registered spend_tags with their deposited amounts
- `SpendTagUsed` — spend_tags that have been spent in a purchase
- `NullifierUsed` — nullifiers consumed (double-spend guard)
- `CommitmentAmounts` — deposits by commitment hash
- `Leaves` + `MerkleRoot` — Merkle tree state
- `RwaPrices` — registered RWA prices

Queries RWA chain (spec 102):
- `ProofHubPurchases` — records written by XCM from ProofHub
- `OwnershipRedeemed` — claims processed
- `Listings` — active asset listings
- `NullifierUsed` — nullifiers on the RWA side

Consistency checks performed:
1. Every `SpendTagUsed` key must exist in `SpendTagValues`
2. `NullifierUsed` count ≥ `SpendTagUsed` count on ProofHub
3. `Leaves` count == `CommitmentAmounts` count (Merkle integrity)
4. RWA purchases count ≤ ProofHub nullifiers (cross-chain consistency)
5. Ownership redeemed ≤ purchases

```bash
node scripts/audit_chain_state.js
# Connects to: ws://127.0.0.1:9947  (ProofHub)
#              ws://127.0.0.1:9955  (RWA chain)
```

---

### register_para.js

Registers a new parachain on the relay chain using sudo.

Takes genesis head and validation WASM as files, calls
`parasSudoWrapper.sudoScheduleParaInitialize` wrapped in `sudo` and
`utility.batchAll`. Logs all events from the finalized block.

```bash
node scripts/register_para.js \
  ws://127.0.0.1:9944 \          # relay RPC
  2000 \                          # parachain ID
  parachain/artifacts/proofhub-genesis-head.bin \
  parachain/artifacts/proofhub-genesis-wasm.wasm \
  //Alice                         # sudo key URI
```

All arguments are positional and optional (defaults shown above).

---

## Network Topology

```
Relay (nulla-relay)   ws://127.0.0.1:9944  (Alice)
                      ws://127.0.0.1:9945  (Bob)

ProofHub  para 2000   ws://127.0.0.1:9947  spec_version 109
RWA chain para 2001   ws://127.0.0.1:9955  spec_version 102
```

## Privacy Protocol Version

These scripts were written for and tested against:

- ProofHub spec_version **109** (Phase 6: spend_tag unlinkability)
- RWA runtime spec_version **102** (Phase 6: xcm_record_purchase with spend_tag)
- Tag: `v1.6.0-private-spend-tag`
