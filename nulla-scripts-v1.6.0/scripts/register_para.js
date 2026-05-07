// Register a parachain on the relay using head/wasm files.
// Usage:
//   node scripts/register_para.js <relayWs> <paraId> <genesisHeadPath> <validationWasmPath> [//SudoUri]
// Example:
//   node scripts/register_para.js ws://127.0.0.1:9945 1000 parachain/artifacts/proofhub-genesis-head.bin parachain/artifacts/proofhub-genesis-wasm.wasm //Alice

const fs = require('fs');
const { ApiPromise, WsProvider, Keyring } = require('@polkadot/api');
const { cryptoWaitReady } = require('@polkadot/util-crypto');

async function main() {
  const relayWs = process.argv[2] || 'ws://127.0.0.1:9945';
  const paraId = parseInt(process.argv[3] || '1000', 10);
  const headPath = process.argv[4] || 'parachain/artifacts/proofhub-genesis-head.bin';
  const wasmPath = process.argv[5] || 'parachain/artifacts/proofhub-genesis-wasm.wasm';
  const sudoUri = process.argv[6] || '//Alice';

  if (!fs.existsSync(headPath)) throw new Error(`Missing head file: ${headPath}`);
  if (!fs.existsSync(wasmPath)) throw new Error(`Missing wasm file: ${wasmPath}`);

  const head = fs.readFileSync(headPath);
  const code = fs.readFileSync(wasmPath);

  await cryptoWaitReady();
  const provider = new WsProvider(relayWs);
  const api = await ApiPromise.create({ provider });

  const keyring = new Keyring({ type: 'sr25519' });
  const sudo = keyring.addFromUri(sudoUri);

  console.log(`Connecting to relay: ${relayWs}`);
  console.log(`Registering ParaId ${paraId} with files:`);
  console.log(`  head: ${headPath} (${head.length} bytes)`);
  console.log(`  code: ${wasmPath} (${code.length} bytes)`);

  // Newer Polkadot runtimes expect 2 args:
  // (paraId, { genesisHead, validationCode, paraKind })
  // where paraKind is an enum, pass as { parachain: true }.
  const genesis = {
    genesisHead: head,
    validationCode: code,
    // ParaKind enum variant; most runtimes expect a unit variant
    paraKind: { parachain: null },
  };
  const schedule = api.tx.parasSudoWrapper.sudoScheduleParaInitialize(paraId, genesis);

  // Wrap the schedule in sudo. In most cases, the initialization already sets the code,
  // so a separate "addTrustedValidationCode" is not required anymore.
  const batch = api.tx.utility.batchAll([
    api.tx.sudo.sudo(schedule),
  ]);

  await new Promise(async (resolve, reject) => {
    try {
      const unsub = await batch.signAndSend(sudo, ({ status, dispatchError, events }) => {
        if (dispatchError) {
          if (dispatchError.isModule) {
            const decoded = api.registry.findMetaError(dispatchError.asModule);
            const { docs, name, section } = decoded;
            console.error(`Dispatch error: ${section}.${name}: ${docs.join(' ')}`);
          } else {
            console.error(`Dispatch error: ${dispatchError.toString()}`);
          }
        }
        if (status.isInBlock) {
          console.log(`Included in block ${status.asInBlock.toHex()}`);
        }
        if (status.isFinalized) {
          console.log(`Finalized in block ${status.asFinalized.toHex()}`);
          events.forEach(({ event }) => {
            console.log(`Event: ${event.section}.${event.method}`);
            try {
              event.data.forEach((d, i) => {
                const t = event.typeDef?.[i]?.type || 'Unknown';
                console.log(`  [${i}] ${t}: ${d.toString()}`);
              });
            } catch (_) {}
          });
          unsub();
          resolve();
        }
      });
    } catch (e) {
      reject(e);
    }
  });

  await api.disconnect();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
