// Explicit opt-in multisig treasury exercise. Runs ONLY inside the fresh internal Docker network of a disposable
// local Koinos chain with the public laboratory genesis (see multisig-local-setup.sh). Synthetic keys only.
// This is an independent client: it builds raw transactions with koilib directly, never through kcli.
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const LAB = process.env.LAB_DIR || '/lab';
const { LocalKoinos } = require(LAB + '/driver/node_modules/@roamin/local-koinos');
const { Contract, Serializer, Signer, Transaction, utils } = require(LAB + '/driver/node_modules/koilib');
const secp = require(LAB + '/driver/node_modules/@noble/secp256k1');

const lk = new LocalKoinos({ rpc: 'http://jsonrpc:8080/', amqp: 'amqp://guest:guest@amqp:5672' });
// local-koinos's published development key for its KOIN account, taken from the package instead of repeated here.
const KOIN_WIF = lk.koin.signer.getPrivateKey('wif');
const EX = '/exercise';
const EXPECTED_CHAIN = 'EiD3i3yxv2aEUIbat5bRSakYgKqim9RCQ0B1w8DMvaCrWw==';
const MAINNET_CHAIN = 'EiBZK_GGVP0H_fXVAM3j6EAuz3-B-l3ejxRSewi7qIBfSA==';
const KOIN_DIR = LAB + '/kca-4fc33bb/contracts/koin';
const PROBE_DIR = LAB + '/v2-lab/probe';
const RC = '200000000';
const UPLOAD_RC = '5000000000';
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const dec = a => Buffer.from(utils.decodeBase58(a));
const random = () => new Signer({ privateKey: crypto.randomBytes(32).toString('hex') });
const byBytes = (a, b) => Buffer.compare(dec(a), dec(b));
let phase = 'start';

// Fixed kernel schema for raw state reads (code, metadata, contract storage).
const f = (type, id) => ({ type, id });
const kernel = new Serializer({ nested: {
  Space: { fields: { system: f('bool', 1), zone: f('bytes', 2), id: f('uint32', 3) } },
  Query: { fields: { space: f('Space', 1), key: f('bytes', 2) } },
  Obj: { fields: { exists: f('bool', 1), value: f('bytes', 2), key: f('bytes', 3) } },
  Result: { fields: { value: f('Obj', 1) } },
  Metadata: { fields: { hash: f('bytes', 1), system: f('bool', 2), call: f('bool', 3), transaction: f('bool', 4), upload: f('bool', 5) } },
} });
async function getObject(space, key, next = false) {
  const args = utils.encodeBase64url(await kernel.serialize({ space, key }, 'Query'));
  const caller = space.system ? {} : { caller_data: { caller: utils.encodeBase58(utils.decodeBase64url(space.zone)), caller_privilege: 'user_mode' } };
  const r = await lk.provider.call('chain.invoke_system_call', { name: next ? 'get_next_object' : 'get_object', args, ...caller });
  return (await kernel.deserialize(r.value ?? '', 'Result')).value || {};
}
async function deployedState(address) {
  const key = utils.encodeBase64url(dec(address));
  const code = await getObject({ system: true, id: 2 }, key);
  const metaObj = await getObject({ system: true, id: 3 }, key);
  const meta = metaObj.exists ? await kernel.deserialize(metaObj.value, 'Metadata') : null;
  // Storage.Obj writes under the EMPTY key: get_next_object('') would skip it, so read both forms.
  const policySpace = { system: false, zone: key, id: 0 };
  const atEmptyKey = await getObject(policySpace, '');
  const after = await getObject(policySpace, '', true);
  return { codeSha256: code.exists ? sha(Buffer.from(utils.decodeBase64url(code.value))) : null, meta, storedPolicy: !!(atEmptyKey.exists || after.exists) };
}

const read = file => JSON.parse(fs.readFileSync(file, 'utf8'));
// CLI-format ABI ("entry-point" as hex string) -> fields koilib 5 encodes with (checked again at every use).
function probeAbi() {
  const abi = read(PROBE_DIR + '/abi/probe.abi');
  for (const m of Object.values(abi.methods)) { m.entry_point = Number(m['entry-point']); m.read_only = m['read-only']; }
  return abi;
}
const write = (file, value) => { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 }); };
async function mine(n = 1) { for (let i = 0; i < n; i++) await lk.produceBlock({ logs: false }); }

let koin, koinAbi, KOIN;
function loadKoin() {
  koinAbi = JSON.parse(fs.readFileSync(KOIN_DIR + '/abi/koin.abi', 'utf8'));
  KOIN = Signer.fromWif(KOIN_WIF).address;
  koin = new Contract({ id: KOIN, abi: koinAbi, provider: lk.provider });
}
async function balance(a) { const { result } = await koin.functions.balance_of({ owner: a }); return BigInt(result?.value || '0'); }
async function allowances(a) { const { result } = await koin.functions.get_allowances({ owner: a, start: '', limit: 10, descending: false }); return result?.allowances || []; }

// Raw transaction builder: explicit header, arbitrary operations, signatures appended separately.
async function tx(payer, operations, opts = {}) {
  const account = opts.payee || payer;
  const header = { chain_id: opts.chainId || EXPECTED_CHAIN, payer, rc_limit: opts.rcLimit || RC, nonce: opts.nonce || await lk.provider.getNextNonce(account) };
  if (opts.payee) header.payee = opts.payee;
  return Transaction.prepareTransaction({ header, operations, signatures: [] });
}
const idBytes = t => Buffer.from(t.id.slice(6), 'hex');
async function sign(t, ...signers) { for (const s of signers) t.signatures.push(utils.encodeBase64url(await s.signHash(idBytes(t)))); return t; }
// A second, different but valid signature by the same key (random nonce instead of RFC 6979).
async function signFresh(t, s) {
  const [sig, rec] = await secp.sign(idBytes(t), s.getPrivateKey('hex'), { recovered: true, canonical: true, der: false, extraEntropy: true });
  t.signatures.push(utils.encodeBase64url(Buffer.concat([Buffer.from([rec + 31]), Buffer.from(sig)]))); return t;
}
// The same signature in non-canonical (high-s) form.
function malleate(sigB64) {
  const b = Buffer.from(utils.decodeBase64url(sigB64)); const n = secp.CURVE.n;
  const s = BigInt('0x' + b.subarray(33).toString('hex'));
  const out = Buffer.concat([Buffer.from([((b[0] - 31) ^ 1) + 31]), b.subarray(1, 33), Buffer.from((n - s).toString(16).padStart(64, '0'), 'hex')]);
  return utils.encodeBase64url(out);
}
async function send(t) {
  try {
    const r = await lk.provider.sendTransaction(t, true); await mine(1);
    const logs = (r.receipt?.logs || []).join(' ').toLowerCase().replace(/[^\x20-\x7e]/g, ' ').slice(0, 200);
    return r.receipt?.reverted ? { outcome: 'reverted', rc: r.receipt.rc_used, detail: logs } : { outcome: 'accepted', rc: r.receipt?.rc_used, events: r.receipt?.events || [], logs };
  } catch (e) {
    const m = String(e.message || e).toLowerCase();
    const known = ['authoriz', 'nonce', 'canonical', 'signature', 'rc', 'mana', 'insufficient', 'chain id'];
    const detail = m.replace(/\b[5kl][1-9a-hj-np-z]{49,51}\b/g, '[redacted-key]').replace(/[^\x20-\x7e]/g, ' ').slice(0, 160);
    return { outcome: 'refused', reason: known.find(k => m.includes(k)) || 'other', detail };
  }
}
// A refusal only counts when it happened for the expected reason (never a Mana/nonce/encoding accident).
const AUTH = /not authorized|authorization failure|authoriz/;
// Treasury-paid transactions whose operations exceed the contract's 8 KB system buffer fail closed in the kernel.
const AUTH_OR_OVERSIZE = /not authorized|authorization failure|authoriz|return buffer is not large enough/;
function expectRefused(r, pattern = AUTH) {
  assert.notEqual(r.outcome, 'accepted', 'unexpectedly accepted');
  assert(pattern.test(r.detail || ''), `refused for an unexpected reason: ${r.outcome} ${r.detail}`);
  return r.outcome + ': ' + (r.detail || '').slice(0, 90);
}
async function transferOp(from, to, value, memo) {
  return (await koin.encodeOperation({ name: 'transfer', args: { from, to, value: String(value), ...(memo ? { memo } : {}) } }));
}

// Canonical-chain evidence for an included transaction: exact body from its block, receipt, height <= LIB.
async function included(id) {
  const rec = await lk.provider.call('transaction_store.get_transactions_by_id', { transaction_ids: [id] });
  const item = rec.transactions?.[0]; assert(item?.containing_blocks?.length === 1, 'transaction indexed in exactly one block');
  const blockId = item.containing_blocks[0];
  const { block_items } = await lk.provider.call('block_store.get_blocks_by_id', { block_ids: [blockId], return_block: true, return_receipt: true });
  const b = block_items[0]; const t = b.block.transactions.find(x => x.id === id); const r = b.receipt.transaction_receipts.find(x => x.id === id);
  assert(t && r && !r.reverted, 'included, not reverted');
  const head = await lk.provider.getHeadInfo(); const height = BigInt(b.block_height);
  assert(height <= BigInt(head.last_irreversible_block), 'irreversible');
  const canon = await lk.provider.call('block_store.get_blocks_by_height', { head_block_id: head.head_topology.id, ancestor_start_height: b.block_height, num_blocks: 1, return_block: false, return_receipt: false });
  assert.equal(canon.block_items[0].block_id, blockId, 'on the canonical chain');
  return { tx: t, receipt: r, height: b.block_height, blockId };
}
function checkUploadTx(t, address, artifactName, operationCount) {
  assert.equal(t.header.payer, address); assert(!t.header.payee, 'no payee');
  assert.equal(t.operations.length, operationCount);
  const up = t.operations[t.operations.length - 1].upload_contract; assert(up, 'last operation is the upload');
  assert.equal(up.contract_id, address);
  assert.equal(sha(Buffer.from(utils.decodeBase64url(up.bytecode))), read(`${EX}/artifacts/${artifactName}/artifact.json`).wasmSha256);
  assert(up.authorizes_call_contract && up.authorizes_transaction_application && up.authorizes_upload_contract, 'all three flags in the included upload');
}

const results = [];
function record(name, data) { results.push({ name, ...data }); console.log('PASS ' + name); write(EX + '/evidence-partial.json', results); }

function treasuryContract(name) {
  const k = read(`${EX}/keys/${name}.json`); const abi = JSON.parse(fs.readFileSync(`${EX}/artifacts/${name}/treasury.abi`, 'utf8'));
  return { keys: k, address: k.treasury.address, signer: Signer.fromWif(k.treasury.wif), owners: k.owners.map(o => Signer.fromWif(o.wif)), contract: new Contract({ id: k.treasury.address, abi, provider: lk.provider }) };
}
async function uploadOp(address, artifactName, flags = { call: true, transaction: true, upload: true }) {
  const dir = `${EX}/artifacts/${artifactName}`;
  return { upload_contract: { contract_id: address, bytecode: utils.encodeBase64url(fs.readFileSync(dir + '/contract.wasm')), abi: fs.readFileSync(dir + '/treasury.abi', 'utf8'),
    authorizes_call_contract: flags.call, authorizes_transaction_application: flags.transaction, authorizes_upload_contract: flags.upload } };
}
// A tiny replacement (the 8-byte empty wasm module, far below the contract's 8 KB system buffer), so an upload
// refusal can only come from authority, never from a buffer overflow. Uploads are refused before any execution.
const EMPTY_WASM = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
function tinyUploadOp(address) {
  return { upload_contract: { contract_id: address, bytecode: utils.encodeBase64url(EMPTY_WASM), authorizes_call_contract: false, authorizes_transaction_application: false, authorizes_upload_contract: false } };
}
// Mint provisioning KOIN (testnet KOIN variant lets the contract key mint; the genesis key pays Mana).
// One transaction for all mints: the mempool limits a payer's pending (not yet irreversible) Mana reservations.
async function fund(...pairs) {
  const minter = new Contract({ id: KOIN, abi: koinAbi, provider: lk.provider }); const operations = [];
  for (const [to, whole] of pairs) operations.push((await minter.functions.mint({ to, value: utils.parseUnits(String(whole), 8) }, { onlyOperation: true })).operation);
  const t = await tx(lk.genesisSigner.address, operations, { rcLimit: '100000000' }); await sign(t, lk.genesisSigner, Signer.fromWif(KOIN_WIF));
  const r = await send(t); assert.equal(r.outcome, 'accepted', 'funding failed: ' + (r.detail || r.outcome));
}

// ---------------------------------------------------------------------------------------------------------- keys
// Five builds: main (5 owners, 3-of-5), allow (3/2), seed (3/2) + seed-evil (attacker owners, same address),
// wrongchain (3/2 built for the Mainnet chain ID, deployed here).
function keys() {
  assert(!fs.existsSync(EX + '/keys'), 'refuse repeated key generation');
  const make = (n, threshold) => {
    const owners = Array.from({ length: n }, random).map(s => ({ address: s.getAddress(), wif: s.getPrivateKey('wif') })).sort((a, b) => byBytes(a.address, b.address));
    const t = random(); return { treasury: { address: t.getAddress(), wif: t.getPrivateKey('wif') }, owners, threshold };
  };
  // Edge case: addresses starting with "11" (a leading zero hash byte, ~1/256).
  const leadingZero = () => { for (;;) { const s = random(); if (s.getAddress().startsWith('11')) return { address: s.getAddress(), wif: s.getPrivateKey('wif') }; } };
  const sets = { main: make(5, 3), allow: make(3, 2), seed: make(3, 2), wrongchain: make(3, 2) };
  sets.main.owners[0] = leadingZero(); sets.main.owners.sort((a, b) => byBytes(a.address, b.address));
  sets.allow.treasury = leadingZero();
  sets['seed-evil'] = { ...make(3, 2), treasury: sets.seed.treasury };
  KOIN || loadKoin();
  for (const [name, k] of Object.entries(sets)) {
    write(`${EX}/keys/${name}.json`, k);
    write(`${EX}/inputs/${name}.json`, { schema: 1, template: 'koinos-multisig-treasury', templateVersion: '1.0.0', network: 'local',
      chainId: name === 'wrongchain' ? MAINNET_CHAIN : EXPECTED_CHAIN, koinContract: KOIN, treasury: k.treasury.address, owners: k.owners.map(o => o.address), threshold: k.threshold });
  }
  console.log('KEYS written (synthetic): ' + Object.keys(sets).join(', '));
}

// ----------------------------------------------------------------------------------------------------- bootstrap
// KOIN, Mainnet-like Mana routing and provisioning. Shared by the contract matrix and the CLI exercise.
async function chainSetup(extraFunding, expectRcOf) {
  phase = 'koin';
  loadKoin(); await mine(1);
  const wasm = fs.readFileSync(KOIN_DIR + '/build/testnet/contract.wasm');
  assert.equal(sha(wasm), '4251a6e9d9c9a37f3bbf67e171f63a7dcad62309e4be7d9da85a74f68520edf7', 'expected lab KOIN build');
  await lk.deployContract(KOIN_WIF, wasm, koinAbi, { mode: 'manual' }, { authorizesCallContract: true, authorizesTransactionApplication: true, authorizesUploadContract: true });
  await lk.setSystemContract(KOIN, true, { mode: 'manual' });
  // the mempool reserves a payer's Mana until the block is irreversible (LIB = head - 60)
  await mine(61);
  await fund([lk.genesisSigner.address, 1000000], ...extraFunding);
  // Mainnet semantics: Mana is KOIN-backed. Route get_account_rc (201) / consume_account_rc (202) to KOIN.
  phase = 'koin-mana';
  const route = (id, ep, contract = KOIN) => ({ set_system_call: { call_id: id, target: { system_call_bundle: { contract_id: contract, entry_point: ep } } } });
  // KOIN's get_account_rc resolves the governance contract by name (get_contract_address, 10001), which Mainnet
  // serves from the name-service contract. LAB ONLY stand-in: every name resolves to an all-zero address.
  const names = random();
  const namesUpload = { upload_contract: { contract_id: names.getAddress(), bytecode: utils.encodeBase64url(fs.readFileSync(`${EX}/artifacts/lab-names/contract.wasm`)) } };
  let n = await send(await sign(await tx(lk.genesisSigner.address, [namesUpload, { set_system_contract: { contract_id: names.getAddress(), system_contract: true } }], { rcLimit: '100000000' }), lk.genesisSigner, names));
  assert.equal(n.outcome, 'accepted', 'lab name service: ' + (n.detail || n.outcome));
  // get_contract_metadata (112): Mainnet routes it to the official system contract (built from the same KOIN source
  // tree); KOIN's checkAccountAuthority needs it whenever a contract is the caller.
  const gcm = random();
  const gcmUpload = { upload_contract: { contract_id: gcm.getAddress(), bytecode: utils.encodeBase64url(fs.readFileSync(`${EX}/artifacts/get-contract-metadata/contract.wasm`)) } };
  n = await send(await sign(await tx(lk.genesisSigner.address, [gcmUpload, { set_system_contract: { contract_id: gcm.getAddress(), system_contract: true } }], { rcLimit: '100000000' }), lk.genesisSigner, gcm));
  assert.equal(n.outcome, 'accepted', 'get_contract_metadata contract: ' + (n.detail || n.outcome));
  const sys = await tx(lk.genesisSigner.address, [route(112, 0x784faa08, gcm.getAddress()), route(10001, 0x01, names.getAddress()), route(201, 0x2d464aab), route(202, 0x80e3f5c9)], { rcLimit: '100000000' });
  let m = await send(await sign(sys, lk.genesisSigner)); assert.equal(m.outcome, 'accepted', 'mana routing: ' + (m.detail || m.outcome));
  await mine(61);
  assert.equal(await lk.provider.getAccountRc(expectRcOf[0]), utils.parseUnits(String(expectRcOf[1]), 8), 'KOIN-backed Mana active');
}
async function bootstrap() {
  const probeKey = random(); const probeAbiJson = probeAbi();
  write(`${EX}/keys/probe.json`, { address: probeKey.getAddress(), wif: probeKey.getPrivateKey('wif') });
  const outsider = random(); write(`${EX}/keys/outsider.json`, { address: outsider.getAddress(), wif: outsider.getPrivateKey('wif') });
  const main = read(`${EX}/keys/main.json`).treasury.address;
  await chainSetup([[probeKey.getAddress(), 1000], [outsider.getAddress(), 1000], ...['main', 'allow', 'seed', 'wrongchain'].map(name => [read(`${EX}/keys/${name}.json`).treasury.address, name === 'main' ? 1000 : 200])], [main, 1000]);
  phase = 'probe-upload';
  const probeUpload = { upload_contract: { contract_id: probeKey.getAddress(), bytecode: utils.encodeBase64url(fs.readFileSync(PROBE_DIR + '/build/release/contract.wasm')), abi: JSON.stringify(probeAbiJson) } };
  let r = await send(await sign(await tx(probeKey.getAddress(), [probeUpload], { rcLimit: UPLOAD_RC }), probeKey)); assert.equal(r.outcome, 'accepted', 'probe upload: ' + (r.detail || r.outcome));
  phase = 'accounts';
  await mine(61);
  console.log('PASS bootstrap: KOIN ' + KOIN + ', probe, provisioning');
}

// --------------------------------------------------------------------------------------------------------- matrix
async function matrix() {
  loadKoin();
  const M = treasuryContract('main'); const outsider = Signer.fromWif(read(`${EX}/keys/outsider.json`).wif);
  const probe = read(`${EX}/keys/probe.json`).address;
  const owners = M.owners; const recipient = random().getAddress();
  const artifact = read(`${EX}/artifacts/main/artifact.json`);

  phase = 'bootstrap-upload';
  {
    const nonceBefore = await lk.provider.getNonce(M.address);
    const t = await sign(await tx(M.address, [await uploadOp(M.address, 'main')], { rcLimit: UPLOAD_RC }), M.signer);
    const r = await send(t); assert.equal(r.outcome, 'accepted', 'bootstrap upload: ' + (r.detail || r.outcome));
    await mine(61);
    const inc = await included(t.id); checkUploadTx(inc.tx, M.address, 'main', 1);
    assert.equal(inc.tx.header.nonce, t.header.nonce);
    const s = await deployedState(M.address);
    assert.equal(s.codeSha256, artifact.wasmSha256); assert(s.meta.call && s.meta.transaction && s.meta.upload && !s.meta.system);
    assert.equal(Buffer.from(utils.decodeBase64url(s.meta.hash)).toString('hex'), '1220' + artifact.wasmSha256, 'metadata multihash');
    assert.equal(s.storedPolicy, false); assert.deepEqual(await allowances(M.address), []);
    assert.equal(Number(nonceBefore), 0); assert.equal(Number(await lk.provider.getNonce(M.address)), 1);
    const { result: p } = await M.contract.functions.get_policy({});
    assert.deepEqual(p.owners, M.keys.owners.map(o => o.address)); assert.equal(p.threshold, 3); assert.equal(p.version || '0', '0');
    const { result: tpl } = await M.contract.functions.get_template({});
    assert.equal(tpl.name, 'koinos-multisig-treasury'); assert.equal(tpl.version, '1.0.0'); assert.equal(tpl.koin_contract, KOIN);
    assert.equal(tpl.min_owners, 3); assert.equal(tpl.max_owners, 15);
    assert(Buffer.from(utils.decodeBase64url(tpl.chain_id)).equals(Buffer.from(utils.decodeBase64url(EXPECTED_CHAIN))), 'template chain id');
    assert(M.keys.owners.some(o => o.address.startsWith('11')), 'leading-zero owner regression present');
    record('bootstrap: canonical irreversible single-op upload (exact body from its block), code + metadata hash, 3 flags, empty policy space, no allowances, nonce 0->1, initial policy v0 (incl. a "11…" owner), template', { transactionId: t.id, block: inc.blockId, height: inc.height, rcUsed: r.rc, wasmSha256: artifact.wasmSha256, wasmSize: artifact.wasmSize });
  }

  phase = 'quorum-subsets';
  {
    let accepted = 0, refused = 0; const rc = {};
    for (let mask = 0; mask < 32; mask++) {
      const set = owners.filter((_, i) => mask & (1 << i));
      const before = await balance(M.address); const credit = await balance(recipient);
      const t = await sign(await tx(M.address, [await transferOp(M.address, recipient, 1000)]), ...set);
      const r = await send(t);
      const after = await balance(M.address);
      if (set.length >= 3) { assert.equal(r.outcome, 'accepted', `subset ${mask} must pass: ${r.detail || r.outcome}`); assert.equal(before - after, 1000n); assert.equal(await balance(recipient) - credit, 1000n, 'recipient credited');
        assert(r.events.some(e => e.name === 'token.transfer_event' && (e.impacted || []).includes(recipient) && (e.impacted || []).includes(M.address)), 'transfer event names treasury and recipient'); accepted++; (rc[set.length] ||= []).push(Number(r.rc)); }
      // zero signatures never reach the contract: the node itself requires signature data
      else { expectRefused(r, set.length ? AUTH : /signature_data/); assert.equal(before, after); refused++; }
    }
    assert.equal(accepted, 16); assert.equal(refused, 16);
    record('all 32 signer subsets of 3-of-5: exactly the 16 with >=3 distinct owners move KOIN', { accepted, refused, rcUsedBySignatures: Object.fromEntries(Object.entries(rc).map(([k, v]) => [k, { min: Math.min(...v), max: Math.max(...v) }])) });
  }

  phase = 'signature-identity';
  {
    const cases = {};
    const before = await balance(M.address);
    let t = await sign(await tx(M.address, [await transferOp(M.address, recipient, 1)]), owners[0], owners[1]); t.signatures.push(t.signatures[0]);
    cases.sameSignatureTwice = expectRefused(await send(t));
    t = await sign(await tx(M.address, [await transferOp(M.address, recipient, 1)]), owners[0], owners[1]); await signFresh(t, owners[0]);
    assert.notEqual(t.signatures[0], t.signatures[2]); cases.sameOwnerTwoDistinctSignatures = expectRefused(await send(t));
    t = await sign(await tx(M.address, [await transferOp(M.address, recipient, 1)]), owners[0], owners[1]); t.signatures.push(malleate(t.signatures[0]));
    cases.highSMalleatedDuplicate = expectRefused(await send(t), /canonical|signature/);
    t = await sign(await tx(M.address, [await transferOp(M.address, recipient, 1)]), owners[0], owners[1], owners[2], outsider);
    cases.quorumPlusNonOwner = expectRefused(await send(t));
    t = await sign(await tx(M.address, [await transferOp(M.address, recipient, 1)]), owners[0], owners[1], owners[2], M.signer);
    cases.quorumPlusTreasuryKey = expectRefused(await send(t));
    t = await sign(await tx(M.address, [await transferOp(M.address, recipient, 1)]), owners[0], owners[1]); t.signatures.push(utils.encodeBase64url(Buffer.alloc(65, 7)));
    cases.quorumMinusOnePlusGarbage = expectRefused(await send(t), /recovery id|signature|public key|canonical/);
    // Well-formed signature by an owner over a different digest: recovers to an unrelated identity in the contract.
    t = await sign(await tx(M.address, [await transferOp(M.address, recipient, 1)]), owners[0], owners[1]);
    t.signatures.push(utils.encodeBase64url(await owners[2].signHash(crypto.createHash('sha256').update('other').digest())));
    cases.quorumMinusOnePlusWrongDigest = expectRefused(await send(t));
    t = await sign(await tx(M.address, [await transferOp(M.address, recipient, 1)]), ...owners, outsider);
    cases.sixSignaturesMoreThanOwners = expectRefused(await send(t));
    assert.equal(await balance(M.address), before);
    record('identity counting: duplicate, distinct-nonce duplicate, high-s, non-owner, treasury key, garbage and excess signatures all refuse', cases);
  }

  phase = 'single-key-bypass';
  {
    const before = await balance(M.address); const cases = {};
    cases.treasuryKeyTransfer = expectRefused(await send(await sign(await tx(M.address, [await transferOp(M.address, recipient, 1)]), M.signer)));
    cases.treasuryKeyApprove = expectRefused(await send(await sign(await tx(M.address, [await koin.encodeOperation({ name: 'approve', args: { owner: M.address, spender: outsider.getAddress(), value: '100' } })]), M.signer)));
    cases.treasuryKeyUploadSameCode = expectRefused(await send(await sign(await tx(M.address, [await uploadOp(M.address, 'main')]), M.signer)), AUTH_OR_OVERSIZE);
    cases.treasuryKeyUploadFlagsOff = expectRefused(await send(await sign(await tx(M.address, [await uploadOp(M.address, 'main', { call: false, transaction: false, upload: false })]), M.signer)), AUTH_OR_OVERSIZE);
    cases.treasuryKeyTinyReplacement = expectRefused(await send(await sign(await tx(M.address, [tinyUploadOp(M.address)]), M.signer)));
    // Outsider pays, so the contract's contract_upload rule itself is what refuses (no size effect).
    cases.outsiderPaysUploadByTreasuryKey = expectRefused(await send(await sign(await tx(outsider.getAddress(), [await uploadOp(M.address, 'main', { call: false, transaction: false, upload: false })], { rcLimit: UPLOAD_RC }), outsider, M.signer)));
    cases.treasuryKeySetPolicy = expectRefused(await send(await sign(await tx(M.address, [await M.contract.encodeOperation({ name: 'set_policy', args: { owners: M.keys.owners.map(x => x.address), threshold: 4 } })]), M.signer)));
    cases.treasuryKeyPaysOutsiderCall = expectRefused(await send(await sign(await tx(M.address, [await transferOp(outsider.getAddress(), recipient, 1)]), M.signer, outsider)));
    cases.outsiderPaysTreasuryKeyTransfer = expectRefused(await send(await sign(await tx(outsider.getAddress(), [await transferOp(M.address, recipient, 1)]), outsider, M.signer)));
    assert.equal(await balance(M.address), before); assert.deepEqual(await allowances(M.address), []);
    const s = await deployedState(M.address); assert.equal(s.codeSha256, artifact.wasmSha256); assert(s.meta.call && s.meta.transaction && s.meta.upload);
    record('original address key alone cannot transfer, approve, upload (same code or flags off), pay Mana or be sponsored', cases);
  }

  phase = 'envelope';
  {
    const q = owners.slice(0, 3); const before = await balance(M.address); const cases = {};
    const o = outsider.getAddress();
    cases.quorumUploadSameCode = expectRefused(await send(await sign(await tx(M.address, [await uploadOp(M.address, 'main')]), ...q)), AUTH_OR_OVERSIZE);
    cases.quorumTinyReplacement = expectRefused(await send(await sign(await tx(M.address, [tinyUploadOp(M.address)]), ...q)));
    cases.outsiderPaysUploadByQuorum = expectRefused(await send(await sign(await tx(o, [await uploadOp(M.address, 'main')], { rcLimit: UPLOAD_RC }), outsider, ...q)));
    cases.quorumApprove = expectRefused(await send(await sign(await tx(M.address, [await koin.encodeOperation({ name: 'approve', args: { owner: M.address, spender: o, value: '100' } })]), ...q)));
    cases.quorumBurn = expectRefused(await send(await sign(await tx(M.address, [await koin.encodeOperation({ name: 'burn', args: { from: M.address, value: '100' } })]), ...q)));
    cases.quorumTwoTransfers = expectRefused(await send(await sign(await tx(M.address, [await transferOp(M.address, recipient, 1), await transferOp(M.address, recipient, 1)]), ...q)));
    cases.quorumTransferPlusPolicy = expectRefused(await send(await sign(await tx(M.address, [await transferOp(M.address, recipient, 1), await M.contract.encodeOperation({ name: 'set_policy', args: { owners: M.keys.owners.map(x => x.address), threshold: 4 } })]), ...q)));
    cases.quorumMemo = expectRefused(await send(await sign(await tx(M.address, [await transferOp(M.address, recipient, 1, 'invoice 7')]), ...q)));
    cases.quorumZeroValue = expectRefused(await send(await sign(await tx(M.address, [await transferOp(M.address, recipient, 0)]), ...q)));
    cases.quorumToSelf = expectRefused(await send(await sign(await tx(M.address, [await transferOp(M.address, M.address, 1)]), ...q)));
    cases.quorumBadRecipientChecksum = await (async () => {
      const op = await transferOp(M.address, recipient, 1); const args = Buffer.from(utils.decodeBase64url(op.call_contract.args));
      const i = args.indexOf(dec(recipient)); args[i + 24] ^= 1; op.call_contract.args = utils.encodeBase64url(args);
      return expectRefused(await send(await sign(await tx(M.address, [op]), ...q)));
    })();
    cases.quorumTransferFromOtherAccount = expectRefused(await send(await sign(await tx(M.address, [await transferOp(o, recipient, 1)]), ...q, outsider)));
    cases.quorumArbitraryContractCall = expectRefused(await send(await sign(await tx(M.address, [await (new Contract({ id: probe, abi: probeAbi(), provider: lk.provider })).encodeOperation({ name: 'balance_of', args: { owner: M.address } })]), ...q)));
    cases.quorumTransferUnknownField = await (async () => {
      const op = await transferOp(M.address, recipient, 1);
      op.call_contract.args = utils.encodeBase64url(Buffer.concat([Buffer.from(utils.decodeBase64url(op.call_contract.args)), Buffer.from([0x48, 0x01])])); // field 9 varint
      return expectRefused(await send(await sign(await tx(M.address, [op]), ...q)));
    })();
    cases.quorumOtherPayer = expectRefused(await send(await sign(await tx(o, [await transferOp(M.address, recipient, 1)]), outsider, ...q)));
    cases.quorumWithPayee = expectRefused(await send(await sign(await tx(M.address, [await transferOp(M.address, recipient, 1)], { payee: o }), ...q, outsider)));
    const probeAbiJson = probeAbi();
    const p = new Contract({ id: probe, abi: probeAbiJson, provider: lk.provider });
    const forward = async (name, call) => {
      const op = await p.encodeOperation({ name, args: { target: call.contract_id, entry_point: call.entry_point, args: '0x' + Buffer.from(utils.decodeBase64url(call.args)).toString('hex') } });
      assert.equal(op.call_contract.entry_point, parseInt(crypto.createHash('sha256').update(name).digest('hex').slice(0, 8), 16), 'probe op encoding');
      assert(op.call_contract.args.length > 40, 'probe op carries the inner call');
      return op;
    };
    // Positive control: the same nested path really moves KOIN when the account is the caller itself.
    const control = await send(await sign(await tx(o, [await forward('forward', (await transferOp(probe, recipient, 1)).call_contract)]), outsider));
    assert.equal(control.outcome, 'accepted', 'probe nested-transfer control: ' + (control.detail || control.outcome));
    const inner = (await transferOp(M.address, recipient, 1)).call_contract;
    cases.quorumNestedViaProbe = expectRefused(await send(await sign(await tx(M.address, [await forward('forward', inner)]), ...q)));
    // Other payer: the wrapper ignores the inner result, so the outer transaction is included; the proof is that
    // KOIN emitted no transfer event (and the treasury balance is unchanged, checked below), while the identical
    // nested path did emit one in the positive control above.
    const ignored = await send(await sign(await tx(o, [await forward('call_ignore', inner)]), outsider, ...q));
    assert.equal(ignored.outcome, 'accepted', 'call_ignore wrapper: ' + (ignored.detail || ignored.outcome));
    assert(!ignored.events.some(e => e.name === 'token.transfer_event'), 'nested transfer must not happen');
    assert(control.events.some(e => e.name === 'token.transfer_event'), 'control transfer happened');
    cases.quorumNestedViaProbeOtherPayer = 'wrapper included, no KOIN transfer event, balance unchanged';
    assert.equal(await balance(M.address), before); assert.deepEqual(await allowances(M.address), []);
    const s = await deployedState(M.address); assert.equal(s.codeSha256, artifact.wasmSha256);
    record('quorum cannot upload, approve, burn, batch, mix, memo, zero, self, bad checksum, other payer, payee or nest', cases);
  }

  phase = 'replay';
  {
    const t = await sign(await tx(M.address, [await transferOp(M.address, recipient, 5)]), ...owners.slice(2));
    const first = await send(t); assert.equal(first.outcome, 'accepted');
    const before = await balance(M.address); const again = expectRefused(await send(JSON.parse(JSON.stringify(t))), /nonce/);
    assert.equal(await balance(M.address), before);
    record('an executed quorum transaction cannot be replayed (treasury nonce)', { replay: again });
  }

  phase = 'policy';
  {
    const cases = {}; const q = owners.slice(0, 3);
    const fresh = [random(), random(), random()].sort((a, b) => byBytes(a.getAddress(), b.getAddress()));
    const addrs = x => x.map(s => s.getAddress ? s.getAddress() : s);
    const bad = {
      thresholdOne: { owners: addrs(fresh), threshold: 1 }, thresholdAll: { owners: addrs(fresh), threshold: 3 },
      twoOwners: { owners: addrs(fresh.slice(0, 2)), threshold: 2 }, sixteenOwners: { owners: Array.from({ length: 16 }, random).map(s => s.getAddress()).sort(byBytes), threshold: 9 },
      unsorted: { owners: addrs([...fresh].reverse()), threshold: 2 }, duplicate: { owners: addrs([fresh[0], fresh[0], fresh[1]]).sort(byBytes), threshold: 2 },
      treasuryAsOwner: { owners: [...addrs(fresh.slice(0, 2)), M.address].sort(byBytes), threshold: 2 },
      minorityThreshold: { owners: Array.from({ length: 6 }, random).map(s => s.getAddress()).sort(byBytes), threshold: 3 },
    };
    for (const [k, args] of Object.entries(bad)) {
      const op = await M.contract.encodeOperation({ name: 'set_policy', args });
      cases[k] = expectRefused(await send(await sign(await tx(M.address, [op]), ...q)));
    }
    const good = { owners: addrs(fresh), threshold: 2 };
    const goodOp = await M.contract.encodeOperation({ name: 'set_policy', args: good });
    cases.validPolicyWithPayee = expectRefused(await send(await sign(await tx(M.address, [goodOp], { payee: outsider.getAddress() }), ...q, outsider)));
    cases.policyUnknownField = await (async () => {
      const op = await M.contract.encodeOperation({ name: 'set_policy', args: good });
      op.call_contract.args = utils.encodeBase64url(Buffer.concat([Buffer.from(utils.decodeBase64url(op.call_contract.args)), Buffer.from([0x48, 0x01])]));
      return expectRefused(await send(await sign(await tx(M.address, [op]), ...q)));
    })();
    cases.twoOldOwners = expectRefused(await send(await sign(await tx(M.address, [goodOp]), ...owners.slice(0, 2))));
    cases.newOwnersOnly = expectRefused(await send(await sign(await tx(M.address, [goodOp]), ...fresh)));
    const pp = new Contract({ id: probe, abi: probeAbi(), provider: lk.provider });
    const nestedPolicy = await pp.encodeOperation({ name: 'forward', args: { target: M.address, entry_point: goodOp.call_contract.entry_point, args: '0x' + Buffer.from(utils.decodeBase64url(goodOp.call_contract.args)).toString('hex') } });
    assert.equal(nestedPolicy.call_contract.entry_point, 0x9dc08e40, 'probe op encoding');
    cases.directCallerNested = expectRefused(await send(await sign(await tx(M.address, [nestedPolicy]), ...q)));
    const { result: still } = await M.contract.functions.get_policy({}); assert.equal(still.version || '0', '0');
    // An old signed payment from before the rotation (same nonce domain) is prepared but held back.
    const held = await sign(await tx(M.address, [await transferOp(M.address, recipient, 7)], { nonce: await lk.provider.getNextNonce(M.address) }), ...q);
    const rotate = await send(await sign(await tx(M.address, [goodOp]), ...q));
    assert.equal(rotate.outcome, 'accepted');
    assert(rotate.events.some(e => e.name === 'treasury.policy_updated'), 'policy event');
    const { result: p } = await M.contract.functions.get_policy({});
    assert.deepEqual(p.owners, good.owners); assert.equal(p.threshold, 2); assert.equal(p.version, '1');
    const s = await deployedState(M.address); assert.equal(s.storedPolicy, true);
    const before = await balance(M.address);
    // authority is checked before the nonce: removed owners fail first; the nonce is spent anyway
    cases.heldOldPaymentAfterRotation = expectRefused(await send(held), /not authorized|nonce/);
    cases.oldQuorumAfterRotation = expectRefused(await send(await sign(await tx(M.address, [await transferOp(M.address, recipient, 1)]), ...owners.slice(0, 3))));
    cases.oneNewOwner = expectRefused(await send(await sign(await tx(M.address, [await transferOp(M.address, recipient, 1)]), fresh[0])));
    assert.equal(await balance(M.address), before);
    const ok = await send(await sign(await tx(M.address, [await transferOp(M.address, recipient, 9)]), fresh[0], fresh[2]));
    assert.equal(ok.outcome, 'accepted'); assert.equal(before - await balance(M.address), 9n);
    record('policy: invalid replacements and wrong quorums refuse; valid rotation by the old quorum is atomic (v1, event); removed owners and stale nonce fail; new quorum works', { ...cases, rotationRcUsed: rotate.rc, newQuorumTransferRcUsed: ok.rc });
    write(`${EX}/keys/main-rotated.json`, { owners: fresh.map(s => ({ address: s.getAddress(), wif: s.getPrivateKey('wif') })), threshold: 2 });

    // Upper bound: 15 owners, threshold 14 (system buffer, signature bound, RC).
    phase = 'max-owners';
    const big = Array.from({ length: 15 }, random).sort((a, b) => byBytes(a.getAddress(), b.getAddress()));
    const bigOp = await M.contract.encodeOperation({ name: 'set_policy', args: { owners: big.map(x => x.getAddress()), threshold: 14 } });
    const toBig = await send(await sign(await tx(M.address, [bigOp]), fresh[0], fresh[1]));
    assert.equal(toBig.outcome, 'accepted', 'rotate to 15/14: ' + (toBig.detail || toBig.outcome));
    const { result: bp } = await M.contract.functions.get_policy({});
    assert.deepEqual(bp.owners, big.map(x => x.getAddress())); assert.equal(bp.threshold, 14); assert.equal(bp.version, '2');
    const b0 = await balance(M.address);
    const thirteen = expectRefused(await send(await sign(await tx(M.address, [await transferOp(M.address, recipient, 1)]), ...big.slice(0, 13))));
    assert.equal(await balance(M.address), b0);
    const fourteen = await send(await sign(await tx(M.address, [await transferOp(M.address, recipient, 1)]), ...big.slice(0, 14)));
    assert.equal(fourteen.outcome, 'accepted', '14 signatures: ' + (fourteen.detail || fourteen.outcome));
    const fifteen = await send(await sign(await tx(M.address, [await transferOp(M.address, recipient, 1)]), ...big));
    assert.equal(fifteen.outcome, 'accepted', '15 signatures: ' + (fifteen.detail || fifteen.outcome));
    assert.equal(b0 - await balance(M.address), 2n);
    record('upper bound: rotation to 15 owners / threshold 14 (v2); 13 signatures refuse, 14 and 15 move KOIN within the 8 KB buffer', { rotationRcUsed: toBig.rc, rc14: fourteen.rc, rc15: fifteen.rc, thirteen });
  }

  phase = 'address-binding';
  {
    // The main artifact uploaded at a different address authorizes nothing there.
    const X = random(); await fund([X.getAddress(), 100]); await mine(61);
    const up = await send(await sign(await tx(X.getAddress(), [await uploadOp(X.getAddress(), 'main')], { rcLimit: UPLOAD_RC }), X)); assert.equal(up.outcome, 'accepted');
    const before = await balance(X.getAddress());
    const r = expectRefused(await send(await sign(await tx(X.getAddress(), [await transferOp(X.getAddress(), recipient, 1)]), ...owners.slice(0, 3))));
    assert.equal(await balance(X.getAddress()), before);
    let policyReadable = true; try { await new Contract({ id: X.getAddress(), abi: M.contract.abi, provider: lk.provider }).functions.get_policy({}); } catch { policyReadable = false; }
    assert.equal(policyReadable, false);
    record('artifact is bound to its treasury address: uploaded elsewhere it authorizes nothing and get_policy fails closed', { transfer: r });
  }

  phase = 'chain-binding';
  {
    const W = treasuryContract('wrongchain');
    const up = await send(await sign(await tx(W.address, [await uploadOp(W.address, 'wrongchain')], { rcLimit: UPLOAD_RC }), W.signer)); assert.equal(up.outcome, 'accepted'); await mine(61);
    const before = await balance(W.address);
    const r = expectRefused(await send(await sign(await tx(W.address, [await transferOp(W.address, recipient, 1)]), ...W.owners)));
    assert.equal(await balance(W.address), before);
    record('artifact is bound to its chain: a Mainnet-bound build refuses every quorum transaction on another chain', { transfer: r });
  }

  phase = 'bootstrap-attack-allowance';
  {
    // The address key approves the probe contract as KOIN spender in the same transaction as the upload. The
    // contract never sees it: KOIN uses an allowance for a contract caller without asking the account. Code hash
    // and flags look correct; only the allowance check (and the 2-operation bootstrap) reveals it.
    const A = treasuryContract('allow');
    const approve = await koin.encodeOperation({ name: 'approve', args: { owner: A.address, spender: probe, value: utils.parseUnits('50', 8) } });
    const boot = await sign(await tx(A.address, [approve, await uploadOp(A.address, 'allow')], { rcLimit: UPLOAD_RC }), A.signer);
    let r = await send(boot); assert.equal(r.outcome, 'accepted');
    await mine(61);
    const inc = await included(boot.id); checkUploadTx(inc.tx, A.address, 'allow', 2);
    assert(inc.tx.operations[0].call_contract, 'verification signal: a second (approve) operation in the bootstrap transaction');
    const s = await deployedState(A.address); assert.equal(s.codeSha256, read(`${EX}/artifacts/allow/artifact.json`).wasmSha256); assert(s.meta.call && s.meta.transaction && s.meta.upload);
    assert.equal(s.storedPolicy, false);
    const list = await allowances(A.address); assert.equal(list.length, 1, 'verification signal: allowance present');
    const p = new Contract({ id: probe, abi: probeAbi(), provider: lk.provider });
    const inner = await transferOp(A.address, outsider.getAddress(), utils.parseUnits('10', 8));
    const fwd = await p.encodeOperation({ name: 'forward', args: { target: KOIN, entry_point: inner.call_contract.entry_point, args: '0x' + Buffer.from(utils.decodeBase64url(inner.call_contract.args)).toString('hex') } });
    assert.equal(fwd.call_contract.entry_point, 0x9dc08e40, 'probe op encoding');
    const before = await balance(A.address);
    r = await send(await sign(await tx(outsider.getAddress(), [fwd]), outsider));
    assert.equal(r.outcome, 'accepted', 'the pre-upload allowance really drains without any owner');
    assert.equal(before - await balance(A.address), 1000000000n);
    record('bootstrap attack 1 (pre-upload KOIN allowance) is real and visible to verification: allowance listed, bootstrap had 2 operations', { allowances: list.length, drainedWithoutOwners: '10 KOIN' });
  }

  phase = 'bootstrap-attack-storage';
  {
    // The key first uploads an attacker-owned build (upload override OFF), seeds an attacker policy through it,
    // then uploads the reviewed build with all flags. Code hash and flags look correct; verification must catch it.
    const S = treasuryContract('seed'); const E = treasuryContract('seed-evil');
    let r = await send(await sign(await tx(S.address, [await uploadOp(S.address, 'seed-evil', { call: true, transaction: true, upload: false })], { rcLimit: UPLOAD_RC }), S.signer)); assert.equal(r.outcome, 'accepted');
    const evilPolicy = { owners: E.keys.owners.map(o => o.address), threshold: 2 };
    r = await send(await sign(await tx(S.address, [await S.contract.encodeOperation({ name: 'set_policy', args: evilPolicy })]), ...E.owners.slice(0, 2))); assert.equal(r.outcome, 'accepted');
    // The interim code overrides transaction application, so the attacker pays the final upload from another
    // account; upload authority is still the plain address key (that interim upload left the upload flag off).
    r = await send(await sign(await tx(outsider.getAddress(), [await uploadOp(S.address, 'seed')], { rcLimit: UPLOAD_RC }), outsider, S.signer)); assert.equal(r.outcome, 'accepted', 'final upload: ' + (r.detail || r.outcome));
    await mine(61);
    const s = await deployedState(S.address);
    assert.equal(s.codeSha256, read(`${EX}/artifacts/seed/artifact.json`).wasmSha256); assert(s.meta.call && s.meta.transaction && s.meta.upload);
    const { result: p } = await S.contract.functions.get_policy({});
    assert.equal(s.storedPolicy, true); assert.equal(p.version, '1'); assert.deepEqual(p.owners, evilPolicy.owners);
    const nonce = Number(await lk.provider.getNonce(S.address)); assert.equal(nonce, 2);
    const before = await balance(S.address);
    r = await send(await sign(await tx(S.address, [await transferOp(S.address, recipient, 1)]), ...E.owners.slice(0, 2)));
    assert.equal(r.outcome, 'accepted', 'the seeded attacker quorum really controls the treasury');
    assert.equal(before - await balance(S.address), 1n);
    record('bootstrap attack 2 (seeded policy storage) is real and visible to verification: stored policy object, version 1, foreign owners, nonce 2 (not 1)', { storedPolicy: s.storedPolicy, version: p.version, nonce });
  }

  write(EX + '/evidence-contract.json', { schema: 1, chainId: EXPECTED_CHAIN, koin: KOIN, mainTreasury: M.address, artifact, results });
  console.log('CONTRACT MATRIX COMPLETE');
}

// ------------------------------------------------------------------------------------------- CLI exercise
// Synthetic members for the installed-CLI exercise: 5 owners (3-of-5, one "11…" address) + one future owner, the
// treasury address key and a recipient. Private test keys stay in the exercise volumes only.
function e2eKeys() {
  assert(!fs.existsSync(EX + '/e2e/keys.json'), 'refuse repeated key generation');
  const k = s => ({ address: s.getAddress(), wif: s.getPrivateKey('wif') });
  let lead; while (!lead) { const s = random(); if (s.getAddress().startsWith('11')) lead = s; }
  const owners = [lead, random(), random(), random(), random()].map(k).sort((a, b) => byBytes(a.address, b.address));
  loadKoin(); const keys = { owners, future: k(random()), treasury: k(random()), recipient: k(random()), koin: KOIN };
  write(EX + '/e2e/keys.json', keys);
  write(`${EX}/inputs/e2e.json`, { schema: 1, template: 'koinos-multisig-treasury', templateVersion: '1.0.0', network: 'local', chainId: EXPECTED_CHAIN, koinContract: KOIN, treasury: keys.treasury.address, owners: owners.map(o => o.address), threshold: 3 });
  console.log('E2E KEYS written (synthetic)');
}
async function e2eChain() {
  const keys = read(EX + '/e2e/keys.json');
  // Only bootstrap provisioning (Mana for the single upload); community funding comes after verification.
  await chainSetup([[keys.treasury.address, 10]], [keys.treasury.address, 10]);
  await mine(61); console.log('PASS e2e chain: KOIN ' + KOIN + ', Mainnet-like Mana, treasury address provisioned with 10 KOIN');
}
async function fundOne(addressText, whole) { loadKoin(); await fund([addressText, Number(whole)]); await mine(61); console.log('FUNDED'); }
async function balanceOf(addressText) { loadKoin(); console.log('BALANCE ' + (await balance(addressText)).toString()); }
// Independent client after the CLI bootstrap: the address key alone can neither pay, transfer, rotate nor upload.
async function e2eBypass() {
  loadKoin(); const keys = read(EX + '/e2e/keys.json'); const T = Signer.fromWif(keys.treasury.wif); const t = keys.treasury.address;
  const abi = JSON.parse(fs.readFileSync(`${EX}/artifacts/e2e/treasury.abi`, 'utf8')); const c = new Contract({ id: t, abi, provider: lk.provider });
  const before = await balance(t); const cases = {};
  cases.transfer = expectRefused(await send(await sign(await tx(t, [await transferOp(t, keys.recipient.address, 1)]), T)));
  cases.setPolicy = expectRefused(await send(await sign(await tx(t, [await c.encodeOperation({ name: 'set_policy', args: { owners: keys.owners.map(o => o.address), threshold: 4 } })]), T)));
  // RC limit within the provisioned Mana, so the refusal comes from authority, not from the mempool's Mana check.
  cases.tinyReplacementPaidByTreasury = expectRefused(await send(await sign(await tx(t, [tinyUploadOp(t)]), T)));
  cases.tinyReplacementPaidByOther = expectRefused(await send(await sign(await tx(lk.genesisSigner.address, [tinyUploadOp(t)], { rcLimit: '100000000' }), lk.genesisSigner, T)));
  assert.equal(await balance(t), before);
  const s = await deployedState(t); const art = read(`${EX}/artifacts/e2e/artifact.json`);
  assert.equal(s.codeSha256, art.wasmSha256); assert(s.meta.call && s.meta.transaction && s.meta.upload && !s.meta.system);
  write(EX + '/e2e/bypass.json', { schema: 1, client: 'independent koilib controller', cases, codeUnchanged: true });
  console.log('PASS independent client: address key alone refused (transfer, set_policy, tiny replacement either payer); code unchanged');
}
// Independent check of the CLI bootstrap: the canonical included upload (exact body from its block), raw bytecode,
// metadata hash, flags, empty policy space, nonce and allowances -- without using kcli.
async function e2eVerify() {
  loadKoin(); const keys = read(EX + '/e2e/keys.json'); const manifest = read(EX + '/e2e/treasury.json'); const t = keys.treasury.address;
  const art = read(`${EX}/artifacts/e2e/artifact.json`);
  const inc = await included(manifest.treasury.bootstrap.transactionId); checkUploadTx(inc.tx, t, 'e2e', 1);
  assert.equal(inc.blockId, manifest.treasury.bootstrap.blockId); assert.equal(Number(inc.tx.header.nonce ? utils.decodeBase64url(inc.tx.header.nonce)[1] : 0), 1);
  assert.equal(sha(inc.tx.operations[0].upload_contract.abi), art.abiSha256);
  const s = await deployedState(t);
  assert.equal(s.codeSha256, art.wasmSha256); assert.equal(Buffer.from(utils.decodeBase64url(s.meta.hash)).toString('hex'), '1220' + art.wasmSha256);
  assert(s.meta.call && s.meta.transaction && s.meta.upload && !s.meta.system); assert.equal(s.storedPolicy, false);
  assert.deepEqual(await allowances(t), []); assert.equal(Number(await lk.provider.getNonce(t)), 1);
  assert.equal(manifest.treasury.codeSha256, art.wasmSha256); assert.deepEqual(manifest.policy, { owners: keys.owners.map(o => o.address), threshold: 3, version: '0' });
  const result = { schema: 1, client: 'independent koilib controller', bootstrapTransaction: inc.tx.id, block: inc.blockId, height: inc.height, operations: inc.tx.operations.length, payer: inc.tx.header.payer, payee: inc.tx.header.payee || null,
    rawBytecodeSha256: s.codeSha256, metadataHash: s.meta.hash, flags: { call: s.meta.call, transaction: s.meta.transaction, upload: s.meta.upload, system: !!s.meta.system }, policySpaceEmpty: !s.storedPolicy, allowances: 0, nonce: 1 };
  write(EX + '/e2e/independent.json', result);
  console.log('PASS independent verification of the CLI bootstrap (canonical body, raw code, metadata, flags, storage, nonce, allowances)');
}
async function producer() {
  // Like a live chain, one block every 3 s, so finality keeps advancing (verify-deployment waits for it); after a
  // submission mine straight through to irreversibility (LIB = head - 60).
  let last = Date.now();
  for (;;) {
    const pending = await lk.provider.call('mempool.get_pending_transactions', { limit: '1' });
    if (pending.pending_transactions?.length) { await mine(62); last = Date.now(); }
    else if (Date.now() - last >= 3000) { await mine(1); last = Date.now(); }
    await new Promise(r => setTimeout(r, 300));
  }
}

// --------------------------------------------------------------------------------------- relay (for kcli later)
async function relay() {
  const chunks = []; let length = 0;
  for await (const chunk of process.stdin) { length += chunk.length; assert(length <= 4194304); chunks.push(chunk); }
  const response = await fetch('http://jsonrpc:8080/', { method: 'POST', headers: { 'content-type': 'application/json' }, body: Buffer.concat(chunks), redirect: 'error', signal: AbortSignal.timeout(20000) });
  const text = await response.text(); assert(text.length <= 4194304);
  await new Promise((resolve, reject) => process.stdout.write(text, e => e ? reject(e) : resolve()));
}

(async () => {
  await lk.awaitChain(); assert.equal(await lk.provider.getChainId(), EXPECTED_CHAIN, 'public chains prohibited');
  switch (process.argv[2]) {
    case 'keys': loadKoin(); keys(); break;
    case 'bootstrap': await bootstrap(); break;
    case 'matrix': await matrix(); break;
    case 'mine': await mine(Number(process.argv[3] || 1)); console.log('MINED'); break;
    case 'relay': await relay(); break;
    case 'e2e-keys': loadKoin(); e2eKeys(); break;
    case 'e2e-chain': await e2eChain(); break;
    case 'e2e-bypass': await e2eBypass(); break;
    case 'e2e-verify': await e2eVerify(); break;
    case 'fund': await fundOne(process.argv[3], process.argv[4]); break;
    case 'balance': await balanceOf(process.argv[3]); break;
    case 'producer': await producer(); break;
    default: throw Error('unsupported local controller action');
  }
})().then(() => process.exit(0)).catch(error => {
  const diagnostic = String(error && error.stack || error).replace(/\b[5KL][1-9A-HJ-NP-Za-km-z]{49,51}\b/g, '[redacted-key]').slice(0, 1500);
  console.error('Local multisig exercise failed at ' + phase + ': ' + diagnostic); process.exit(1);
});
