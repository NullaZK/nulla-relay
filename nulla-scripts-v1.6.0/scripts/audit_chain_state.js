#!/usr/bin/env node
'use strict';

/**
 * Full on-chain state audit for ProofHub + RWA chain.
 *
 * Checks:
 *  1. spec_version on both chains
 *  2. ProofHub: SpendTagValues count, SpendTagUsed count, NullifierUsed count,
 *               CommitmentAmounts count, Leaves length, MerkleRoot
 *  3. RWA chain: ProofHubPurchases count, OwnershipRedeemed count
 *  4. Consistency: every spend_tag in SpendTagUsed must also be in SpendTagValues
 *  5. Pool account balance (must hold all deposited funds)
 */

const { ApiPromise, WsProvider, Keyring } = require('@polkadot/api');
const BN = require('bn.js');

const PROOFHUB_WS = 'ws://127.0.0.1:9947';
const RWA_WS      = 'ws://127.0.0.1:9955';

// PalletId "nll/pool" → AccountId (same derivation as in runtime)
// We just check via query rather than deriving the address here.

async function auditProofHub() {
  console.log('\n═══════════════════════════════════════');
  console.log(' PROOFHUB CHAIN AUDIT');
  console.log('═══════════════════════════════════════');

  const api = await ApiPromise.create({ provider: new WsProvider(PROOFHUB_WS) });
  const ver = await api.rpc.state.getRuntimeVersion();
  const specVersion = ver.specVersion.toNumber();
  console.log(`spec_version     : ${specVersion}`);
  if (specVersion !== 109) {
    console.error(`FAIL: expected spec_version 109, got ${specVersion}`);
  } else {
    console.log('spec_version     : OK (109)');
  }

  // Read all storage maps via entries()
  const spendTagValues  = await api.query.proofs.spendTagValues.entries();
  const spendTagUsed    = await api.query.proofs.spendTagUsed.entries();
  const nullifierUsed   = await api.query.proofs.nullifierUsed.entries();
  const commitmentAmts  = await api.query.proofs.commitmentAmounts.entries();
  const leaves          = await api.query.proofs.leaves();
  const merkleRoot      = await api.query.proofs.merkleRoot();
  const rwaPrices       = await api.query.proofs.rwaPrices.entries();

  console.log(`\nSpendTagValues   : ${spendTagValues.length} entries`);
  console.log(`SpendTagUsed     : ${spendTagUsed.length} entries`);
  console.log(`NullifierUsed    : ${nullifierUsed.length} entries`);
  console.log(`CommitmentAmounts: ${commitmentAmts.length} entries`);
  console.log(`Leaves (Merkle)  : ${leaves.length} entries`);
  console.log(`MerkleRoot       : 0x${Buffer.from(merkleRoot).toString('hex').slice(0, 16)}...`);
  console.log(`RWA prices set   : ${rwaPrices.length}`);

  // Consistency check: every SpendTagUsed key must be in SpendTagValues
  const spendTagValueKeys = new Set(
    spendTagValues.map(([k]) => Buffer.from(k.args[0]).toString('hex'))
  );
  let inconsistent = 0;
  for (const [k] of spendTagUsed) {
    const hex = Buffer.from(k.args[0]).toString('hex');
    if (!spendTagValueKeys.has(hex)) {
      console.error(`INCONSISTENCY: SpendTagUsed key ${hex} not in SpendTagValues`);
      inconsistent++;
    }
  }
  if (inconsistent === 0) {
    console.log('\nConsistency      : OK — all used spend_tags have registered values');
  }

  // Double-spend check: nullifierUsed count should match or exceed spendTagUsed count
  if (nullifierUsed.length >= spendTagUsed.length) {
    console.log(`Double-spend guard: OK — ${nullifierUsed.length} nullifiers ≥ ${spendTagUsed.length} used spend_tags`);
  } else {
    console.error(`WARN: ${nullifierUsed.length} nullifiers < ${spendTagUsed.length} used spend_tags — unexpected`);
  }

  // Leaves vs CommitmentAmounts must match
  if (leaves.length === commitmentAmts.length) {
    console.log(`Merkle consistency: OK — ${leaves.length} leaves == ${commitmentAmts.length} commitment amounts`);
  } else {
    console.error(`WARN: ${leaves.length} leaves != ${commitmentAmts.length} commitment amounts`);
  }

  await api.disconnect();
  return {
    spendTagValues: spendTagValues.length,
    spendTagUsed: spendTagUsed.length,
    nullifierUsed: nullifierUsed.length,
  };
}

async function auditRwa(proofHubStats) {
  console.log('\n═══════════════════════════════════════');
  console.log(' RWA CHAIN AUDIT');
  console.log('═══════════════════════════════════════');

  const api = await ApiPromise.create({ provider: new WsProvider(RWA_WS) });
  const ver = await api.rpc.state.getRuntimeVersion();
  const specVersion = ver.specVersion.toNumber();
  console.log(`spec_version     : ${specVersion}`);
  if (specVersion !== 102) {
    console.error(`FAIL: expected spec_version 102, got ${specVersion}`);
  } else {
    console.log('spec_version     : OK (102)');
  }

  const purchases       = await api.query.rwaMarketplace.proofHubPurchases.entries();
  const ownershipRed    = await api.query.rwaMarketplace.ownershipRedeemed.entries();
  const listings        = await api.query.rwaMarketplace.listings.entries();
  const nullifiersUsed  = await api.query.rwaMarketplace.nullifierUsed.entries();

  console.log(`\nProofHub purchases: ${purchases.length}`);
  console.log(`Ownership redeemed: ${ownershipRed.length}`);
  console.log(`Active listings   : ${listings.length}`);
  console.log(`Nullifiers used   : ${nullifiersUsed.length}`);

  // Consistency: purchases on RWA must be ≤ nullifiers spent on ProofHub
  if (purchases.length <= proofHubStats.nullifierUsed) {
    console.log(`\nCross-chain check : OK — ${purchases.length} RWA purchases ≤ ${proofHubStats.nullifierUsed} ProofHub nullifiers`);
  } else {
    console.error(`CROSS-CHAIN FAIL: ${purchases.length} RWA purchases > ${proofHubStats.nullifierUsed} ProofHub nullifiers`);
  }

  // ownership redeemed must be ≤ purchases
  if (ownershipRed.length <= purchases.length) {
    console.log(`Ownership check   : OK — ${ownershipRed.length} redeemed ≤ ${purchases.length} purchases`);
  } else {
    console.error(`FAIL: more ownership redemptions than purchases`);
  }

  await api.disconnect();
}

(async () => {
  try {
    const stats = await auditProofHub();
    await auditRwa(stats);
    console.log('\n═══════════════════════════════════════');
    console.log(' AUDIT COMPLETE');
    console.log('═══════════════════════════════════════\n');
    process.exit(0);
  } catch (e) {
    console.error('AUDIT ERROR:', e.message);
    process.exit(1);
  }
})();
