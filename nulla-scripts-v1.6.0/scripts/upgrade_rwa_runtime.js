#!/usr/bin/env node
'use strict';

const { ApiPromise, WsProvider, Keyring } = require('@polkadot/api');
const fs = require('fs');
const path = require('path');

const WASM_PATH = path.join(__dirname, '../target/release/wbuild/rwa-runtime/rwa_runtime.compact.compressed.wasm');
const RWA_WS = 'ws://127.0.0.1:9955';

(async () => {
  console.log('Connecting to RWA chain at', RWA_WS);
  const provider = new WsProvider(RWA_WS);
  const api = await ApiPromise.create({ provider });

  const keyring = new Keyring({ type: 'sr25519' });
  const alice = keyring.addFromUri('//Alice');

  const ver = await api.rpc.state.getRuntimeVersion();
  console.log('Current spec_version:', ver.specVersion.toNumber());
  console.log('Current spec_name:', ver.specName.toHuman());

  if (!fs.existsSync(WASM_PATH)) {
    console.error('WASM file not found:', WASM_PATH);
    process.exit(1);
  }
  const wasm = fs.readFileSync(WASM_PATH);
  console.log('WASM size:', wasm.length, 'bytes');

  console.log('Submitting sudo.sudo(system.setCode)...');
  await new Promise((res, rej) => {
    api.tx.sudo.sudo(
      api.tx.system.setCode('0x' + wasm.toString('hex'))
    ).signAndSend(alice, { nonce: -1 }, ({ status, dispatchError }) => {
      if (dispatchError) {
        const err = dispatchError.isModule
          ? api.registry.findMetaError(dispatchError.asModule)
          : { docs: [dispatchError.toString()] };
        return rej(new Error('Dispatch error: ' + JSON.stringify(err)));
      }
      if (status.isInBlock) {
        console.log('In block:', status.asInBlock.toString());
      }
      if (status.isFinalized) {
        console.log('Finalized:', status.asFinalized.toString());
        res();
      }
    }).catch(rej);
  });

  console.log('Waiting 10s for runtime upgrade to take effect...');
  await new Promise(r => setTimeout(r, 10000));

  const ver2 = await api.rpc.state.getRuntimeVersion();
  console.log('New spec_version:', ver2.specVersion.toNumber());
  console.log('xcmRecordPurchase present:', !!(api.tx.rwaMarketplace && api.tx.rwaMarketplace.xcmRecordPurchase));
  console.log('redeemRwaOwnership present:', !!(api.tx.rwaMarketplace && api.tx.rwaMarketplace.redeemRwaOwnership));

  if (ver2.specVersion.toNumber() !== 102) {
    console.error('UPGRADE FAILED: spec_version is', ver2.specVersion.toNumber(), '(expected 102)');
    process.exit(1);
  }
  console.log('SUCCESS: RWA runtime upgraded to spec_version=102');
  process.exit(0);
})().catch(e => {
  console.error('ERROR:', e.message);
  process.exit(1);
});
