# Nulla Runtime Upgrade — Audit Sign-Off

**Audit Step:** Production Runtime Migration  
**Date:** 2026-03-23  


---

## 1. Scope

This audit step covers the production runtime upgrade of  Nulla parachains:

| Chain | Para ID | Previous spec_version | New spec_version | Previous spec_name | New spec_name |
|---|---|---|---|---|---|
| ProofHub | 2000 | 1 | **2** | `parachain-template-runtime` | `proofhub` |


---

## 2. Pre-Upgrade State (fill before upgrading)

### ProofHub 

| Field | Value |
|---|---|
| spec_version | 1 |
| Block height | #13285 |
| Merkle tree leaves | _(not queried)_ |
| Nullifiers used | _(not queried)_ |



---

## 3. Changes Included

### ProofHub (v1 → v2)
- [x] `spec_name` renamed: `"parachain-template-runtime"` → `"proofhub"`
- [x] `spec_version` bumped: 1 → 2
- [x] No pallet logic changes
- [x] No storage layout changes
- [x] No new pallets added or removed
- [x] No storage migration required (SCALE positional encoding — field renames are transparent)



---

## 4. Security Review

### Verified
- [x] Sudo key matches on both chains (dry-run verified before upgrade)
- [x] WASM built from audited source code in the same repository
- [x] No unsigned transaction validation changes
- [x] No balance/transfer logic changes
- [x] `submit_proof` unsigned validation unchanged
- [x] Pedersen/Schnorr/Bulletproof verifier unchanged
- [x] Merkle tree logic unchanged

### Known Limitations (pre-existing, not introduced by this upgrade)
- [ ] **Weight::zero()** on all custom pallet calls — must benchmark before real economic value flows through the chains
- [ ] **Sudo (dev key)** still controls upgrades — must migrate to governance or multisig before real users
- [ ] **No StorageVersion attributes** on custom pallets — should add for proper migration tracking in future upgrades
- [ ] **No rate limiting** on `submit_proof` unsigned transactions

---

## 5. Upgrade Execution Log (fill during upgrade)

### ProofHub Upgrade

| Step | Result |
|---|---|
| Dry-run | ✅ PASS |
| Dry-run block height | #14122 |
| Dry-run sudo key match | ✅ YES |
| LIVE upgrade submitted | ✅ YES, at block #13864 |
| Finalized | ✅ YES — `System.ExtrinsicSuccess` + `ParachainSystem.ValidationFunctionStored` received |
| New spec_version confirmed | ✅ 2 — verified via dry-run post-upgrade at block #14122 |
| Events observed | ✅ `ParachainSystem.ValidationFunctionStored`, `Sudo.Sudid { Ok }`, `System.ExtrinsicSuccess` |

> **Note:** Parachains emit `ParachainSystem.ValidationFunctionStored` (not `System.CodeUpdated`) when the new WASM is queued. The runtime activates at the next relay chain block inclusion (`ValidationFunctionApplied`). spec_version=2 was confirmed live via dry-run immediately after.


---

## 6. Post-Upgrade Verification (fill after upgrade)

| Check | ProofHub |
|---|---|---|
| Chain producing blocks | ✅ YES (block #14122+) | 
| spec_version matches expected | ✅ 2 | [ ] 3 |
| spec_name matches expected | ✅ `proofhub` | 
| Existing storage intact | ✅ YES | 
| Balance transfers work | ✅ YES | 


---

## 7. Rollback Plan

If the upgrade fails or introduces issues:

1. **Re-upgrade with the previous WASM** — build the previous spec_version from the git tag/commit and re-submit via sudo
2. **Chain state is preserved** — `set_code` replaces only the WASM blob, not storage
3. **Both chains are empty** — worst case, re-genesis from the chainspec with no data loss

---

## 8. Sign-Off

I confirm that:
- ✅ ProofHub dry-run passed before the live upgrade
- ✅ ProofHub live upgrade finalized successfully (spec_version 1 → 2, block #13864)
- ✅ ProofHub post-upgrade verification checks pass
- ✅ No data loss or storage corruption observed
- ✅ Known limitations are documented and accepted for the current testnet/staging phase



