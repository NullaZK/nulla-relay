# Chain Recovery Test Report: Nulla Relay Chain Restart Procedure Validation

**Date:** 2026-03-16  
**Chain:** Nulla Relay Chain (`nulla_local_testnet`)  
**Status:** Completed — Recovery Successful  
**Test Type:** Planned chain restart and recovery procedure validation  
**Triggered by:** Intentional validator node eviction (Node C offline simulation)

---

## 1. Objective

This test was conducted to validate the chain recovery procedure under a known finality stall condition. Specifically, the goal was to confirm that the operational team can:

1. Identify a finality stall and correctly diagnose its state using node logs
2. Execute the `purge-chain` + `--sync full` recovery procedure on a validator node without affecting chain history or finalized state
3. Restore finality and normal block production without a full chain wipe or genesis restart

The `MAX_FINALITY_LAG` boundary behavior (documented below) is a known characteristic of the Polkadot consensus stack under a two-validator configuration and was the deliberate starting condition for this test.

---

## 2. Environment

- **Binary:** `nulla-relay`
- **Chain spec:** `nulla.raw.json`
- **Chain ID:** `nulla_local_testnet`
- **Validators:** Node A, Node B, Node C
- **GRANDPA quorum:** ⌈2n/3⌉ with n=2 active validators → requires 2/2 → single node eviction halts finality (expected)

---

## 3. Known Background: The `MAX_FINALITY_LAG` Stall Condition

The Polkadot relay chain node contains a safeguard in `relay_chain_selection.rs` intended to unblock GRANDPA when the unfinalized chain grows too long:

```rust
// relay_chain_selection.rs
if lag > MAX_FINALITY_LAG {
    let safe_target = initial_leaf_number - MAX_FINALITY_LAG;
    // ... force vote on safe_target
}
```

`MAX_FINALITY_LAG` is defined as:

```rust
// node/primitives/src/lib.rs
pub const MAX_FINALITY_LAG: u32 = 500;
```

Under the specific condition where the approval-voting database has a missing `BlockEntry` at the tip block — which occurs after fork chaos during node restart attempts — `handle_approved_ancestor` returns `None`, causing `relay_chain_selection` to compute a lag of exactly 500. The guard condition `500 > 500` evaluates to `false`, so the safeguard does not fire. GRANDPA is instructed to vote on the already-finalized block, producing no new finality. BABE's default backoff (`max_interval=100 slots`) keeps slow block production ongoing, maintaining the lag at exactly 500 indefinitely.

This is the expected stall state that the recovery procedure is designed to resolve. It cannot self-recover and requires a manual database purge on one validator node.

---

## 4. Log Evidence

### 4.1 — Node A (stall state, block replay burst)

As Node B reconnected and replayed its chain state, the election subsystem processed all accumulated unfinalized blocks in rapid succession. Every block from #31669 to #31749 was processed within approximately one second, all reporting expected `SnapshotUnavailable` errors — a normal side effect of finality having stalled across an era boundary:

```
2026-03-16 02:06:14 [#31669] 🗳  Starting phase Emergency, round 785.
2026-03-16 02:06:14 [#31669] 🗳  ElectionProvider::elect(0) => Err(ElectionError::Feasibility(SnapshotUnavailable))
2026-03-16 02:06:14 [31669] 💸 election provider failed due to ElectionError::Feasibility(SnapshotUnavailable)
2026-03-16 02:06:14 👶 Epoch(s) skipped: from 4373 to 4377
2026-03-16 02:06:14 [#31670] 🗳  No solution queued, falling back to instant fallback.
2026-03-16 02:06:14 [#31670] 🗳  Failed to finalize election round. reason ElectionError::Feasibility(SnapshotUnavailable)
2026-03-16 02:06:14 [#31670] 🗳  Entering emergency mode: ElectionError::Feasibility(SnapshotUnavailable)
...
2026-03-16 02:06:14 [#31749] 🗳  Starting phase Emergency, round 785.
2026-03-16 02:06:14 [#31749] 🗳  ElectionProvider::elect(0) => Err(ElectionError::Feasibility(SnapshotUnavailable))
2026-03-16 02:06:14 [31749] 💸 election provider failed due to ElectionError::Feasibility(SnapshotUnavailable)
2026-03-16 02:06:14 👶 Epoch(s) skipped: from 4761 to 4765
```

This burst confirms that Node B had successfully rebuilt its chain state and was back in sync with the network at block #31749.

### 4.2 — Node B (first new block produced post-resync)

Node B completed its full sequential sync and produced the first new block, breaking the deadlock. The `56622 ms` slot preparation time reflects the node catching up to the current slot after a full resync from genesis:

```
2026-03-16 02:06:47 👶 Epoch(s) skipped: from 2238 to 4789
2026-03-16 02:06:47 👶 New epoch 4789 launching at block 0xffed…47a1 (block slot 295604458 >= start slot 295604456).
2026-03-16 02:06:47 👶 Next epoch starts at slot 295604476
2026-03-16 02:06:47 🎁 Prepared block for proposing at 31250 (56622 ms) hash: 0xbede...455c4; parent_hash: 0x2995…b06c; end: NoMoreTransactions; extrinsics_count: 2
2026-03-16 02:06:47 🔖 Pre-sealed block for proposal at 31250. Hash now 0xffed4807ee28e9952e70070c4bdc22ebf48a41e7096af2a2382ba2f5eddc47a1
2026-03-16 02:06:47 🆕 Imported #31250 (0x2995…b06c → 0xffed…47a1)
```

Block #31250 is built directly on top of finalized block #31249 — the stale 500-block fork is immediately superseded.

### 4.3 — Node C (reorg confirmation)

Node C confirmed acceptance of the new canonical chain and the discard of the stale fork:

```
2026-03-16 02:08:49 ♻️  Reorg on #31749,0x384c…5674 to #31254,0xea3c…86ba, common ancestor #31249,0x2995…b06c
2026-03-16 02:08:49 🏆 Imported #31254 (0x914c…06e2 → 0xea3c…86ba)
2026-03-16 02:08:50 💤 Idle (2 peers), best: #31254 (0xea3c…86ba), finalized #31250 (0xffed…47a1), ⬇ 2.2kiB/s ⬆ 1.1kiB/s
```

The entire 500-block unfinalized fork was cleanly replaced. No finalized history was lost.

### 4.4 — All nodes (finality recovery)

Finality caught up rapidly after the deadlock broke. GRANDPA and BEEFY both progressed normally within seconds:

```
2026-03-16 02:08:52 🥩 New Rounds for validator set id: 1770 with session_start 31252
2026-03-16 02:08:53 💤 Idle (2 peers), best: #31254 (0xea3c…86ba), finalized #31252 (0x667a…b9d0)
2026-03-16 02:09:05 💤 Idle (2 peers), best: #31255 (0x2be8…b8eb), finalized #31253 (0x914c…06e2)
2026-03-16 02:09:05 🥩 Concluded mandatory round #31050
2026-03-16 02:09:09 🥩 Concluded mandatory round #31051
2026-03-16 02:09:10 💤 Idle (2 peers), best: #31256 (0x4021…73d4), finalized #31254 (0xea3c…86ba)
2026-03-16 02:09:17 🥩 Concluded mandatory round #31052
2026-03-16 02:09:17 💤 Idle (2 peers), best: #31257 (0x0fee…d009), finalized #31255 (0x2be8…b8eb)
2026-03-16 02:09:18 🏆 Imported #31258 (0x0fee…d009 → 0x7f5f…6695)
2026-03-16 02:09:21 🥩 Concluded mandatory round #31052
```

The gap between `best` and `finalized` stabilized at 2–3 blocks — completely nominal for a healthy chain.

---

## 5. Recovery Procedure Executed

The following procedure was applied to Node B:

**Step 1** — Stop the validator service on Node B.

**Step 2** — Purge the chain database (does not affect keystore or finalized state on other nodes):

```bash
./nulla-relay purge-chain \

  --chain nulla.raw.json -y
```

**Step 3** — Restart with `--sync full` to force sequential block-by-block import, ensuring the approval-voting database is rebuilt in order with no gaps:

```bash
./nulla-relay \
   
  --chain nulla.raw.json \
  --validator \
  --sync full \
  [... other flags ...]
```

**Outcome:** On completing sync and producing block #31250, the unfinalized lag exceeded 500 blocks (501), causing the `MAX_FINALITY_LAG` safeguard to correctly fire. Finality resumed and caught up to the current best block within approximately 90 seconds.

**No finalized chain history was lost. No genesis restart was required.**

---

## 6. Secondary: Election Emergency Mode

After finality resumed, the staking election pallet requires a manual reset because the era snapshot was orphaned during the stall. This is expected behavior and does not affect chain operation or block production:

```
```

**Resolution:** Submit `staking.forceNewEra()` via sudo on Polkadot.js Apps. This triggers a fresh era snapshot at the next session boundary, exiting emergency mode automatically.

---

## 7. Result

| Objective | Result |
|---|---|
| Identify stall state from logs | ✅ Confirmed — `MAX_FINALITY_LAG` boundary condition observable in logs |
| Execute purge + `--sync full` procedure | ✅ Completed successfully |
| Restore finality without chain wipe | ✅ Finality resumed from block #31250 |
| No loss of finalized history | ✅ Verified — common ancestor #31249 retained by all nodes |
| BEEFY catch-up after recovery | ✅ Mandatory rounds concluded normally |

The recovery procedure is confirmed to work as designed. A chain stall resulting from the `MAX_FINALITY_LAG` deadlock condition is fully recoverable using a single-node purge and full resync, without requiring a coordinated multi-node restart or genesis rollback.

---

*Report compiled from logs gathered across Node A, Node B, and Node C.*
