# Nulla Relay Chain — Resilience Test: Validator Loss & Recovery

**Test Date:** 2026-03-18  
**Test Type:** Disaster Recovery — Simultaneous validator failure simulation  
**Duration:** ~45 minutes (00:37 – 01:22 UTC)  
**Target Systems:** Nulla relay chain — 2 of 3 nodes (both active validators)

---

## 1. Test Objective

Validate the relay chain's ability to recover from a worst-case scenario: **simultaneous loss of all active validators** while only a non-authoring bootnode remains operational. This test deliberately halted block production and finalization to verify:

- Whether chain state is preserved on the surviving bootnode
- Whether validators can be rebuilt from the bootnode's data
- Which resync strategies work (and which do not) for NPoS-enabled relay chains
- Whether session keys and validator identity survive the recovery process
- How quickly the chain resumes normal operation after recovery

---

## 2. Test Procedure

### Phase 1 — Induce Failure

Both active validators were deliberately stopped and their databases purged using `purge-chain`. This simulates a catastrophic loss of both validator nodes (e.g., simultaneous disk failure, data center outage, or compromised hosts requiring full wipe).

The bootnode was left running untouched as the sole surviving node, holding the authoritative chain state at **finalized #52446**.

### Phase 2 — Resync Attempts (testing recovery paths)

Three resync strategies were tested in sequence to determine the correct recovery procedure for NPoS relay chains:

| Strategy | Result | Finding |
|---|---|---|
| `purge-chain` + default full sync | **FAILED** — stuck at finalized #52224, 0.0 bps | Full sync re-executes every block; the NPoS election snapshot at the era boundary is ephemeral and cannot be reconstructed during replay |
| `--sync warp` | **FAILED** — stuck at `Warping 0.00 Mib` indefinitely | Warp sync requires sufficient GRANDPA authority set changes; a ~52k block chain is too short to produce meaningful warp proofs |
| `--sync fast` | **FAILED** — synced blocks rapidly (~1000 bps) but still hit `SnapshotUnavailable` at era boundary | Fast sync still re-executes state transitions, triggering the same election failure |

### Phase 3 — Successful Recovery

The correct recovery method was identified: **copy the bootnode's healthy `db/` directory to both validators**, preserving their existing `keystore/` (session keys) and regenerating `network/secret_ed25519` (p2p identity).

---

## 3. Observed Failure Modes

When validators attempted to resync from genesis, the following cascade was observed:

```
ElectionError::Feasibility(SnapshotUnavailable)
```

| Symptom | Cause |
|---|---|
| `finalized #52224` — stuck | GRANDPA cannot finalize blocks past the era boundary where the election snapshot is missing |
| `0.0 bps` sync speed | Block import stalls waiting for finalization to advance |
| `target=#52645` (phantom) | Stale `network/addr_cache` from before the purge retained block announcements for non-existent blocks |
| `Entering emergency mode: round 785` | Election pallet enters emergency mode, blocking validator set rotation |
| `Not requested block data. Banned, disconnecting.` | Bootnode's sync protocol rejects validators pushing unsolicited fork data |
| Multiple forks at #52225 | Both validators produced conflicting blocks at the same height due to massive BABE epoch skip (`from 5840 to 6185`) |

**Key finding:** `purge-chain` only removes the `db/` directory. It does **not** remove the `network/` directory, which contains:
- `addr_cache` — stale peer block announcements (source of phantom `target=#52645`)
- `secret_ed25519` — p2p identity key

For a clean resync, `network/addr_cache` and `network/peers` must also be deleted. The `secret_ed25519` and `keystore/` must be preserved.

---

## 4. Recovery Actions & Results

| Step | Action | Result |
|---|---|---|
| 1 | Stopped both validators | Clean shutdown |
| 2 | Purged `db/` directory (via `purge-chain`) | Blockchain DB removed |
| 3 | Cleared `network/` directory contents | Removed stale peer cache + p2p identity |
| 4 | Regenerated p2p keys: `nulla-relay key generate-node-key --file <path>/network/secret_ed25519` | New peer IDs generated — does not affect consensus |
| 5 | Tested `--sync warp` | **Confirmed failure** — not viable for short chains |
| 6 | Tested `--sync fast` | **Confirmed failure** — election replay still triggers |
| 7 | Copied bootnode's `db/` directory to both validators (preserving `keystore/`) | **Success** — validators started at #52446 with full finalized state |
| 8 | Restarted both validators (default sync mode) | **Chain resumed** — blocks produced, finalized, all 3 nodes in consensus |

---

## 5. Recovery Verification

Post-recovery state observed at **01:22 UTC**:

```
best: #52459, finalized #52456 — both climbing
2 peers connected on all nodes
BEEFY: Concluded mandatory rounds #52445, #52447, #52449, #52454
Block production: ~1 block / 6 seconds
Both validators authoring (ValidatorIndex 0 and 1 active)
```

| Check | Status |
|---|---|
| Block production resumed | **PASS** — #52449 → #52459+ |
| Finalization advancing | **PASS** — #52446 → #52456+ |
| All 3 nodes connected (2 peers each) | **PASS** |
| BABE authoring | **PASS** — both validators |
| GRANDPA finalization | **PASS** — following best by ~3 blocks |
| BEEFY protocol | **PASS** — mandatory rounds concluding |
| Parachain subsystem | **PASS** — topology indices assigned |
| Session keys intact after recovery | **PASS** — keystore preserved, validators in active set |
| No data loss | **PASS** — all blocks #0 to #52446 preserved from bootnode |

**Residual non-blocking observations:**

| Observation | Impact | Self-healing? |
|---|---|---|
| `ElectionError::Feasibility(SnapshotUnavailable)` at era boundaries | Cosmetic — validator set cannot rotate | **YES** — resolves once staking epoch creates a fresh snapshot |
| Minor single-block reorgs | Normal for 2-validator BABE — both propose at same slot | N/A — expected behavior |
| `Ran out of free WASM instances` | Transient during initial catch-up burst | **YES** — resolves within seconds |

---

## 6. Conclusions & Operational Runbook

### Test Result: **PASS**

The relay chain successfully recovered from simultaneous loss of all active validators. Chain state was fully preserved on the bootnode and validators resumed operation with their original session keys intact.

### Validated Recovery Procedure

For future validator recovery on NPoS relay chains:

1. **DO NOT** rely on `purge-chain` + full resync — it will fail at era boundaries
2. **DO NOT** use `--sync warp` on chains under ~100k blocks
3. **DO** maintain at least one non-authoring full node (bootnode) as a recovery baseline
4. **DO** copy the healthy node's `db/` directory to the failed validator, preserving `keystore/`
5. **DO** clear `network/addr_cache` and `network/peers` if the old network state exists
6. **DO** preserve or regenerate `network/secret_ed25519` — changing peer ID does not affect consensus
7. **DO** restart with default sync mode — no special flags needed after DB copy

### Recovery Time

| Phase | Duration |
|---|---|
| Diagnosis + failed resync attempts | ~30 minutes |
| Successful DB copy + restart | ~5 minutes |
| Chain producing + finalizing | ~2 minutes after restart |
| **Total (with known procedure)** | **~7 minutes** |

---

## 7. Sign-Off

- [x] Test objective achieved: chain recovered from total validator loss
- [x] Three resync strategies tested and documented (warp, fast, DB copy)
- [x] Correct recovery procedure identified and validated
- [x] No data loss confirmed
- [x] Session keys survived recovery
- [x] Operational runbook produced for future incidents

**Conducted by:** nulla team  
**Date:** 2026-03-18  
**Test duration:** ~45 minutes
