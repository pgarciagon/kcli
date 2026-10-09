// Separately authorized official-testnet rehearsal helpers (never part of `npm test`, never Mainnet). Independent
// koilib client against https://testnet.koinosfoundation.org/jsonrpc; synthetic test-only keys.
// usage: KCLI_ROOT=<installed kcli checkout> node multisig-testnet-tools.cjs <action> <work dir> [args]
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const ROOT = process.env.KCLI_ROOT; assert(ROOT, 'set KCLI_ROOT');
const { Contract, Provider, Serializer, Signer, Transaction, utils } = require(path.join(ROOT, 'node_modules', 'koilib'));
const MP = require(path.join(ROOT, 'dist', 'multisig-protocol'));
const RPC = 'https://testnet.koinosfoundation.org/jsonrpc';
const CHAIN = 'EiAIKVvm6-V2qmsmUvPJy09vCCLbtn9lHFpwrJbcTIEWRQ==';
const KOIN = '1FaSvLjQJsCJKq5ybmGsMMQs8RQYyVv8ju';
const p = new Provider(RPC);
const [action, W, ...args] = process.argv.slice(2);
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const read = f => JSON.parse(fs.readFileSync(f, 'utf8'));
const write = (f, v) => fs.writeFileSync(f, JSON.stringify(v, null, 2) + '\n', { mode: 0o600 });
const random = () => new Signer({ privateKey: crypto.randomBytes(32).toString('hex') });
const k = s => ({ address: s.getAddress(), wif: s.getPrivateKey('wif') });
const koin = new Contract({ id: KOIN, abi: MP.KOIN_ABI, provider: p });
const balance = async a => BigInt((await koin.functions.balance_of({ owner: a })).result?.value || '0');
const f = (type, id) => ({ type, id });
const kernel = new Serializer({ nested: {
  Space: { fields: { system: f('bool', 1), zone: f('bytes', 2), id: f('uint32', 3) } }, Query: { fields: { space: f('Space', 1), key: f('bytes', 2) } },
  Obj: { fields: { exists: f('bool', 1), value: f('bytes', 2), key: f('bytes', 3) } }, Result: { fields: { value: f('Obj', 1) } },
  Metadata: { fields: { hash: f('bytes', 1), system: f('bool', 2), call: f('bool', 3), transaction: f('bool', 4), upload: f('bool', 5) } } } });
async function getObject(space, key, next = false) {
  const a = utils.encodeBase64url(await kernel.serialize({ space, key }, 'Query'));
  const caller = space.system ? {} : { caller_data: { caller: utils.encodeBase58(utils.decodeBase64url(space.zone)), caller_privilege: 'user_mode' } };
  const r = await p.call('chain.invoke_system_call', { name: next ? 'get_next_object' : 'get_object', args: a, ...caller });
  return (await kernel.deserialize(r.value ?? '', 'Result')).value || {};
}
async function tx(payer, operations, rcLimit) {
  return Transaction.prepareTransaction({ header: { chain_id: CHAIN, payer, rc_limit: rcLimit, nonce: await p.getNextNonce(payer) }, operations, signatures: [] });
}
async function sign(t, ...signers) { for (const s of signers) t.signatures.push(utils.encodeBase64url(await s.signHash(Buffer.from(t.id.slice(6), 'hex')))); return t; }
async function send(t) {
  try { const r = await p.sendTransaction(t, true); return { outcome: r.receipt?.reverted ? 'reverted' : 'accepted', rc: r.receipt?.rc_used }; }
  catch (e) { return { outcome: 'refused', detail: String(e.message || e).replace(/\b[5KL][1-9A-HJ-NP-Za-km-z]{49,51}\b/g, '[redacted-key]').slice(0, 160) }; }
}
async function waitIncluded(id) {
  for (let i = 0; i < 100; i++) {
    const r = await p.call('transaction_store.get_transactions_by_id', { transaction_ids: [id] });
    if (r.transactions?.[0]?.containing_blocks?.length) return r.transactions[0].containing_blocks[0];
    await new Promise(res => setTimeout(res, 3000));
  }
  throw Error('transaction not included in time');
}
function funder(file) { const j = read(file); const s = Signer.fromWif(j.wif); assert.equal(s.getAddress(), j.address, 'funder key/address'); return s; }

(async () => {
  assert.equal(await p.getChainId(), CHAIN, 'not the official testnet chain');
  switch (action) {
    case 'precheck': {
      // The rehearsal needs kernel reads (code hash, flags, storage) through invoke_system_call.
      const m = await getObject({ system: true, id: 3 }, utils.encodeBase64url(utils.decodeBase58(KOIN)));
      assert(m.exists, 'chain.invoke_system_call unavailable or KOIN metadata missing');
      const fb = await balance(funder(args[0]).getAddress()); assert(fb >= 2500000000n, 'funder needs >= 25 tKOIN');
      console.log('PRECHECK ok: invoke_system_call available, funder tKOIN ' + Number(fb) / 1e8); break;
    }
    case 'keys': {
      assert(!fs.existsSync(path.join(W, 'keys.json')), 'refuse repeated key generation');
      let lead; while (!lead) { const s = random(); if (s.getAddress().startsWith('11')) lead = s; }
      const owners = [lead, random(), random(), random(), random()].map(k).sort((a, b) => MP.compareAddresses(a.address, b.address));
      const keys = { owners, future: k(random()), treasury: k(random()), recipient: k(random()), koin: KOIN };
      write(path.join(W, 'keys.json'), keys);
      write(path.join(W, 'inputs.json'), { schema: 1, template: 'koinos-multisig-treasury', templateVersion: '1.0.0', network: 'testnet', chainId: CHAIN, koinContract: KOIN, treasury: keys.treasury.address, owners: owners.map(o => o.address), threshold: 3 });
      console.log('KEYS (synthetic, test-only) treasury ' + keys.treasury.address); break;
    }
    case 'estimate-upload': {
      // Same bytecode/ABI uploaded to a throwaway address, paid by the funder, with broadcast:false (not persisted).
      const F = funder(args[0]); const x = random(); const dir = path.join(W, 'artifact');
      const op = { upload_contract: { contract_id: x.getAddress(), bytecode: utils.encodeBase64url(fs.readFileSync(path.join(dir, 'contract.wasm'))), abi: fs.readFileSync(path.join(dir, 'treasury.abi'), 'utf8'), authorizes_call_contract: true, authorizes_transaction_application: true, authorizes_upload_contract: true } };
      const t = await sign(await tx(F.getAddress(), [op], '2000000000'), F, x);
      const r = await p.sendTransaction(t, false);
      console.log('UPLOAD_RC ' + r.receipt.rc_used); break;
    }
    case 'fund': {
      const F = funder(args[0]); const to = args[1]; const raw = MP.parseAmount(args[2]);
      const t = await sign(await tx(F.getAddress(), [await MP.encodeTransfer(F.getAddress(), KOIN, to, raw)], '50000000'), F);
      const r = await send(t); assert.equal(r.outcome, 'accepted', 'funding: ' + (r.detail || r.outcome));
      await waitIncluded(t.id); console.log('FUNDED ' + args[2] + ' tKOIN'); break;
    }
    case 'verify': {
      // Independent check of the kcli bootstrap: canonical included body, raw code, metadata, flags, storage, nonce.
      const keys = read(path.join(W, 'keys.json')); const manifest = read(path.join(W, 'treasury.json')); const art = read(path.join(W, 'artifact', 'artifact.json'));
      const t = keys.treasury.address, key = utils.encodeBase64url(utils.decodeBase58(t));
      const blockId = await waitIncluded(manifest.treasury.bootstrap.transactionId);
      const { block_items } = await p.call('block_store.get_blocks_by_id', { block_ids: [blockId], return_block: true, return_receipt: true });
      const b = block_items[0];
      assert(b && b.block_id === blockId && b.block?.id === blockId && b.block.header?.height === b.block_height && b.receipt?.id === blockId && b.receipt.height === b.block_height, 'RPC returned exactly the requested block');
      const inc = b.block.transactions.find(x => x.id === manifest.treasury.bootstrap.transactionId); const rec = b.receipt.transaction_receipts.find(x => x.id === inc.id);
      assert(inc && rec && !rec.reverted); assert.equal(inc.operations.length, 1); const up = inc.operations[0].upload_contract;
      assert.equal(inc.header.payer, t); assert(!inc.header.payee); assert.equal(up.contract_id, t);
      assert.equal(sha(Buffer.from(utils.decodeBase64url(up.bytecode))), art.wasmSha256); assert(up.authorizes_call_contract && up.authorizes_transaction_application && up.authorizes_upload_contract);
      assert.equal(blockId, manifest.treasury.bootstrap.blockId, 'same block as the manifest');
      const head = await p.getHeadInfo(); assert(BigInt(b.block_height) <= BigInt(head.last_irreversible_block), 'irreversible');
      const canon = await p.call('block_store.get_blocks_by_height', { head_block_id: head.head_topology.id, ancestor_start_height: b.block_height, num_blocks: 1, return_block: false, return_receipt: false });
      assert.equal(canon.block_items[0].block_id, blockId, 'canonical');
      const code = await getObject({ system: true, id: 2 }, key); const metaObj = await getObject({ system: true, id: 3 }, key); const meta = await kernel.deserialize(metaObj.value, 'Metadata');
      assert(code.exists, 'raw bytecode readable'); const raw = sha(Buffer.from(utils.decodeBase64url(code.value)));
      assert.equal(raw, art.wasmSha256, 'raw bytecode = artifact');
      assert.equal(Buffer.from(utils.decodeBase64url(meta.hash)).toString('hex'), '1220' + art.wasmSha256); assert(meta.call && meta.transaction && meta.upload && !meta.system);
      const space = { system: false, zone: key, id: 0 }; assert(!(await getObject(space, '')).exists && !(await getObject(space, '', true)).exists, 'policy storage empty');
      assert.equal(Number(await p.getNonce(t)), 1); assert.deepEqual((await koin.functions.get_allowances({ owner: t, start: '', limit: 1, descending: false })).result?.allowances || [], []);
      write(path.join(W, 'independent.json'), { schema: 1, client: 'independent koilib (testnet RPC)', bootstrapTransaction: inc.id, block: blockId, height: b.block_height, operations: 1, rawBytecodeSha256: raw, metadataSha256: art.wasmSha256, flags: { call: true, transaction: true, upload: true, system: false }, policySpaceEmpty: true, nonce: 1, allowances: 0 });
      console.log('PASS independent verification of the testnet bootstrap'); break;
    }
    case 'bypass': {
      // The address key alone: refused at submission (no Mana is spent on a refused transaction).
      const keys = read(path.join(W, 'keys.json')); const T = Signer.fromWif(keys.treasury.wif); const t = keys.treasury.address;
      const c = new Contract({ id: t, abi: MP.TREASURY_ABI, provider: p }); const before = await balance(t); const cases = {};
      // A refusal at submission must leave nonce and Mana untouched (Mana may only regenerate upward).
      const state = async () => ({ nonce: String(await p.getNonce(t)), rc: BigInt(await p.getAccountRc(t)) });
      const refused = async (r, pattern, before) => {
        assert.notEqual(r.outcome, 'accepted', 'unexpectedly accepted'); assert.equal(r.outcome, 'refused', 'refused before inclusion, not reverted');
        assert(pattern.test(r.detail || ''), 'unexpected reason: ' + r.detail);
        const after = await state(); assert.equal(after.nonce, before.nonce, 'nonce unchanged'); assert(after.rc >= before.rc, 'no Mana spent');
        return r.detail.slice(0, 90);
      };
      let s0 = await state(); cases.transfer = await refused(await send(await sign(await tx(t, [await MP.encodeTransfer(t, KOIN, keys.recipient.address, 1n)], '10000000'), T)), /authoriz/, s0);
      s0 = await state(); cases.setPolicy = await refused(await send(await sign(await tx(t, [await c.encodeOperation({ name: 'set_policy', args: { owners: keys.owners.map(o => o.address), threshold: 4 } })], '10000000'), T)), /authoriz/, s0);
      const empty = { upload_contract: { contract_id: t, bytecode: utils.encodeBase64url(Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0])), authorizes_call_contract: false, authorizes_transaction_application: false, authorizes_upload_contract: false } };
      s0 = await state(); cases.tinyReplacement = await refused(await send(await sign(await tx(t, [empty], '10000000'), T)), /authoriz/, s0);
      assert.equal(await balance(t), before);
      write(path.join(W, 'bypass.json'), { schema: 1, client: 'independent koilib (testnet RPC)', cases, nonceAndManaUnchanged: true });
      console.log('PASS independent client: address key alone refused (transfer, set_policy, upload)'); break;
    }
    default: throw Error('unknown action');
  }
})().then(() => process.exit(0)).catch(e => { console.error('testnet tool failed: ' + String(e.message || e).replace(/\b[5KL][1-9A-HJ-NP-Za-km-z]{49,51}\b/g, '[redacted-key]').slice(0, 400)); process.exit(1); });
