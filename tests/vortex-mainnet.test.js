// Public-chain IDs here are synthetic fixtures, never public RPC transactions.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn, spawnSync } = require('node:child_process');
const { utils } = require('koilib');
const V = require('../dist/vortex');
const N = require('../dist/vortex-network');
const P = require('../dist/vortex-protocol');
const F = require('../dist/secure-files');
const X = require('./vortex-fixture');
const urls = ['https://rpc-one.kcli.dev/', 'https://rpc-two.kcli.dev/'];
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'kcli-mainnet-fixture-')); fs.chmodSync(dir, 0o700);
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const f = X.fixture(dir); f.dir = dir; f.manifest.schema = 2;
  f.manifest.network = { name: 'mainnet', chainId: N.MAINNET_CHAIN, rpcs: urls.map((url, i) => ({ url, operator: 'synthetic-operator-' + i })) };
  const keys = crypto.generateKeyPairSync('ed25519');
  const der = keys.publicKey.export({ type: 'spki', format: 'der' }); f.reviewKey = P.sha(der); f.reviewFile = path.join(dir, 'review.json');
  f.authenticate = () => {
    fs.writeFileSync(f.manifestFile, JSON.stringify(f.manifest), { mode: 0o600 });
    const manifestSha256 = P.sha(fs.readFileSync(f.manifestFile));
    f.attestation = { schema: 1, manifestSha256, publicKey: utils.encodeBase64url(der), signature: utils.encodeBase64url(crypto.sign(null, Buffer.from('kcli-vortex-manifest-v2\n' + manifestSha256), keys.privateKey)) };
    fs.writeFileSync(f.reviewFile, JSON.stringify(f.attestation), { mode: 0o600 });
    f.ctx = V.loadVortex(f.manifestFile, f.abiFile, f.reviewFile, f.reviewKey);
  };
  f.authenticate(); return f;
}
async function online(t, f, first = {}, second = {}) {
  const defaults = { chainId: N.MAINNET_CHAIN, time: String(Date.now() - 1000), root: utils.encodeBase64url(Buffer.from('1220' + P.sha('synthetic-state-root'), 'hex')) };
  const primary = await X.rpcFixture(f, { ...defaults, ...first }); t.after(primary.close);
  const witness = await X.rpcFixture(f, { ...defaults, ...second }); t.after(witness.close);
  const original = global.fetch;
  global.fetch = (url, options) => {
    assert(urls.includes(url), 'fixture must never reach an actual public RPC');
    return original(url === urls[0] ? primary.provider.rpc : witness.provider.rpc, options);
  };
  t.after(() => { global.fetch = original; });
  return { primary, witness, provider: V.vortexProvider(f.ctx, urls[0], urls[1]) };
}
async function prepare(f, p) { return V.prepareVortex(f.ctx, p, await V.encodeAction(f.ctx, 'pause', {}), '200000000'); }
async function signed(f, pkg) {
  const id = pkg.transaction.id;
  const a = await V.appendSignature(f.ctx, pkg, X.admins[0], id, 'admin'), b = await V.appendSignature(f.ctx, pkg, X.admins[1], id, 'admin');
  return V.appendSignature(f.ctx, await V.mergePackages(f.ctx, [a, b]), X.payer, id, 'payer');
}
test('mainnet inputs require a cryptographically authenticated exact manifest and trusted fingerprint', t => {
  const f = fixture(t);
  assert.throws(() => V.loadVortex(f.manifestFile, f.abiFile), /requires --review/);
  assert.throws(() => V.loadVortex(f.manifestFile, f.abiFile, f.reviewFile, '00'.repeat(32)), /fingerprint/);
  const a = structuredClone(f.attestation); a.signature = utils.encodeBase64url(Buffer.alloc(64)); fs.writeFileSync(f.reviewFile, JSON.stringify(a));
  assert.throws(() => V.loadVortex(f.manifestFile, f.abiFile, f.reviewFile, f.reviewKey), /signature/);
  f.authenticate(); f.manifest.policy.payer = X.bridge.address; fs.writeFileSync(f.manifestFile, JSON.stringify(f.manifest));
  assert.throws(() => V.loadVortex(f.manifestFile, f.abiFile, f.reviewFile, f.reviewKey), /separate identities/);
  f.manifest.policy.payer = X.payer.address; f.manifest.contract.codeSha256 = '00'.repeat(32); fs.writeFileSync(f.manifestFile, JSON.stringify(f.manifest));
  assert.throws(() => V.loadVortex(f.manifestFile, f.abiFile, f.reviewFile, f.reviewKey), /exact manifest/);
});
test('mainnet permits existing compatible addresses but refuses public testnets and unreviewed source variants', t => {
  const f = fixture(t); f.manifest.contract.address = '1aqHtNRDkiAZeFtuM8fRFuurcje6eHqF8'; f.authenticate();
  assert.equal(f.ctx.contract.getId(), f.manifest.contract.address);
  for (const mutate of [m => m.schema = 1, m => m.network.name = 'testnet', m => m.network.chainId = N.TESTNET_CHAINS[0], m => m.source.commit = '00'.repeat(20), m => m.source.variant = 'v1', m => m.policy.reviewed = false, m => m.network.rpcs[1].operator = m.network.rpcs[0].operator, m => m.network.rpcs[1].url = m.network.rpcs[0].url]) {
    const m = structuredClone(f.manifest); mutate(m); assert.throws(() => V.validateManifest(m));
  }
});
test('public transport refuses insecure or ambiguous URLs, implicit peers and write-capable witnesses', async t => {
  const f = fixture(t);
  for (const url of ['http://rpc-one.kcli.dev/', 'https://localhost/', 'https://127.0.0.1/', 'https://10.0.0.1/', 'https://rpc.local/', 'https://user:pass@rpc-one.kcli.dev/', urls[0] + '?token=secret', urls[0] + '#fragment', 'https://rpc-one.kcli.dev']) assert.throws(() => new V.VortexProvider(url, 'mainnet'));
  assert.throws(() => V.vortexProvider(f.ctx, urls[0]), /Explicit primary/);
  assert.throws(() => V.vortexProvider(f.ctx, urls[0], urls[0]), /Explicit primary/);
  assert.throws(() => V.vortexProvider(f.ctx, urls[0], 'https://unreviewed.kcli.dev/'), /authenticated manifest/);
  const p = V.vortexProvider(f.ctx, ...urls);
  await assert.rejects(() => p.witness.call('chain.submit_transaction', {}), /read-only/);
  await assert.rejects(() => p.call('chain.submit_block', {}), /Unsupported/);
  await assert.rejects(() => prepare(f, new V.VortexProvider('http://127.0.0.1:1')), /RPC request failed/);
});
test('public RPC requests preserve TLS defaults, forbid redirects and withhold malformed or secret responses', async t => {
  const original = global.fetch; t.after(() => { global.fetch = original; });
  const provider = new V.VortexProvider(urls[0], 'mainnet', true);
  global.fetch = async (url, options) => {
    assert.equal(url, urls[0]); assert.equal(options.redirect, 'error'); assert.equal(options.method, 'POST'); assert(options.signal);
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { chain_id: N.MAINNET_CHAIN } }));
  };
  assert.equal(await provider.getChainId(), N.MAINNET_CHAIN);
  for (const body of ['{"id":1,"id":1}', JSON.stringify({ jsonrpc: '2.0', id: 2, result: {} }), JSON.stringify({ jsonrpc: '2.0', id: 1, error: { message: 'synthetic-secret' } }), 'x'.repeat(1048577)]) {
    global.fetch = async () => new Response(body);
    await assert.rejects(() => provider.getChainId(), e => /details withheld/.test(e.message) && !e.message.includes('synthetic-secret'));
  }
  const old = process.env.NODE_TLS_REJECT_UNAUTHORIZED; process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  try { assert.throws(() => new V.VortexProvider(urls[0], 'mainnet'), /certificate verification/); }
  finally { if (old === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED; else process.env.NODE_TLS_REJECT_UNAUTHORIZED = old; }
});
test('two advancing mainnet fixtures prepare unsigned with unchanged protected state and exact ID', async t => {
  const f = fixture(t), rpc = await online(t, f, { advancing: true }, { advancing: true });
  const pkg = await prepare(f, rpc.provider);
  assert.equal(pkg.transaction.header.chain_id, N.MAINNET_CHAIN); assert.equal(pkg.transaction.signatures.length, 0);
  assert.equal(P.transactionId(pkg.transaction), pkg.transaction.id); assert.equal(pkg.snapshot.head.height, '101');
  assert.equal(rpc.primary.state.sends + rpc.witness.state.sends, 0);
  const ready = await signed(f, pkg); await V.preflightVortex(f.ctx, rpc.provider, ready);
  assert.equal(F.canonical({ ...ready.transaction, signatures: [] }), F.canonical(pkg.transaction));
});
test('independent RPC height lag within the bound is checked at common heights without requiring equal heads', async t => {
  const f = fixture(t), rpc = await online(t, f, {}, { height: 95 });
  assert.equal((await prepare(f, rpc.provider)).snapshot.head.height, '100');
});
test('protected deltas, malformed or unavailable receipts fail while unrelated writes are permitted', async t => {
  const f = fixture(t), rpc = await online(t, f, { advancing: true }, { advancing: true });
  const zone = utils.encodeBase64url(utils.decodeBase58(X.bridge.address));
  const unrelated = { object_space: { zone: utils.encodeBase64url(utils.decodeBase58(X.payer.address)), id: 100 }, key: '' };
  rpc.primary.state.deltas = [unrelated]; await prepare(f, rpc.provider);
  for (const delta of [{ object_space: { zone, id: 201 }, key: '' }, { object_space: { system: true, id: 2 }, key: zone }, { object_space: { system: true, id: 3 }, key: zone }, { object_space: { system: true, id: 1 }, key: '' }, { object_space: { system: true, id: 4 }, key: utils.encodeBase64url(utils.decodeBase58(X.payer.address)) }, { object_space: { system: 'invalid', id: 1 }, key: '' }]) {
    rpc.primary.state.deltas = [delta]; await assert.rejects(() => prepare(f, rpc.provider), /state changed|object space/);
  }
  rpc.primary.state.deltas = []; rpc.primary.state.missingBlockReceipt = true;
  await assert.rejects(() => prepare(f, rpc.provider), /receipt chain/);
});
test('independent chain, code, ABI, authority, state, nonce and Mana disagreements refuse preparation', async t => {
  const f = fixture(t), rpc = await online(t, f);
  for (const [key, value] of [['chainId', X.chainId], ['code', Buffer.from('wrong-code')], ['abiText', '{}'], ['authority', { upload: false }], ['admins', [X.admins[0].address]], ['validators', [X.validators[0].address]], ['paused', true], ['nonce', 'KAE='], ['mana', '1']]) {
    const old = rpc.witness.state[key]; rpc.witness.state[key] = value;
    await assert.rejects(() => prepare(f, rpc.provider)); rpc.witness.state[key] = old;
  }
  assert.equal(rpc.primary.state.sends + rpc.witness.state.sends, 0);
});
test('forked or stale heads and excessive height skew fail closed before signing or sending', async t => {
  const f = fixture(t), rpc = await online(t, f);
  rpc.witness.state.fork = true; await assert.rejects(() => prepare(f, rpc.provider), /canonical chain/); rpc.witness.state.fork = false;
  rpc.witness.state.forkAtHeight = 90; await assert.rejects(() => prepare(f, rpc.provider), /irreversible height/); delete rpc.witness.state.forkAtHeight;
  const root = rpc.witness.state.root; rpc.witness.state.root = utils.encodeBase64url(Buffer.from('1220' + P.sha('different-state-root'), 'hex'));
  await assert.rejects(() => prepare(f, rpc.provider), /same read anchor/); rpc.witness.state.root = root;
  rpc.witness.state.time = String(Date.now() - 120001); await assert.rejects(() => prepare(f, rpc.provider), /stale/);
  rpc.witness.state.time = String(Date.now() - 1000); rpc.witness.state.height = 117;
  await assert.rejects(() => prepare(f, rpc.provider), /too far apart/);
  rpc.witness.state.height = 100; rpc.primary.state.advancing = true; rpc.primary.state.fork = true;
  await assert.rejects(() => prepare(f, rpc.provider), /no longer canonical/);
});
test('fresh mainnet preflight preserves signed bodies and refuses changed authority or payer state', async t => {
  const f = fixture(t), rpc = await online(t, f), pkg = await signed(f, await prepare(f, rpc.provider));
  const exact = F.canonical(pkg); await V.preflightVortex(f.ctx, rpc.provider, pkg);
  rpc.primary.state.nonce = rpc.witness.state.nonce = 'KAE=';
  await assert.rejects(() => V.preflightVortex(f.ctx, rpc.provider, pkg), /nonce/);
  rpc.primary.state.nonce = rpc.witness.state.nonce = 'KAA=';
  rpc.primary.state.config.epoch = rpc.witness.state.config.epoch = '2';
  await assert.rejects(() => V.preflightVortex(f.ctx, rpc.provider, pkg), /stale/);
  assert.equal(F.canonical(pkg), exact); assert.equal(rpc.primary.state.sends, 0);
});
test('mainnet delayed actions reject expiry and consumed proposals at fresh preflight without repairing signatures', async t => {
  const f = fixture(t), now = Date.now() - 1000;
  const state = { paused: true, proposal: { eta: String(now - 86400000 + 1000), nonce: '1', epoch: '1', kind: 0 }, time: String(now) };
  const rpc = await online(t, f, state, structuredClone(state));
  const pkg = await signed(f, await V.prepareVortex(f.ctx, rpc.provider, await V.encodeAction(f.ctx, 'unpause', {}), '200000000'));
  const exact = F.canonical(pkg); await V.preflightVortex(f.ctx, rpc.provider, pkg);
  rpc.primary.state.time = rpc.witness.state.time = String(now + 1001);
  await assert.rejects(() => V.preflightVortex(f.ctx, rpc.provider, pkg), /expired/);
  rpc.primary.state.time = rpc.witness.state.time = String(now);
  rpc.primary.state.proposal.eta = rpc.witness.state.proposal.eta = '0';
  await assert.rejects(() => V.preflightVortex(f.ctx, rpc.provider, pkg), /stale/);
  assert.equal(F.canonical(pkg), exact); assert.equal(rpc.primary.state.sends, 0);
});
test('mainnet completion needs both canonical receipts, independent LIB and verified resulting state', async t => {
  const f = fixture(t), rpc = await online(t, f), pkg = await signed(f, await prepare(f, rpc.provider));
  rpc.primary.state.tx = rpc.witness.state.tx = pkg.transaction;
  for (const endpoint of [rpc.primary, rpc.witness]) { endpoint.state.irreversible = true; endpoint.state.paused = true; endpoint.state.config.pauseNonce = '1'; }
  assert.equal((await V.reconcileVortex(f.ctx, rpc.provider, pkg)).status, 'irreversible-and-state-verified');
  rpc.witness.state.lib = '99'; assert.equal((await V.reconcileVortex(f.ctx, rpc.provider, pkg)).status, 'included-successfully'); rpc.witness.state.lib = '100';
  rpc.witness.state.missingReceipt = true; await assert.rejects(() => V.reconcileVortex(f.ctx, rpc.provider, pkg), /receipt/); rpc.witness.state.missingReceipt = false;
  rpc.witness.state.reverted = true; await assert.rejects(() => V.reconcileVortex(f.ctx, rpc.provider, pkg), /disagrees/); rpc.witness.state.reverted = false;
  rpc.witness.state.included = structuredClone(pkg.transaction); rpc.witness.state.included.signatures.pop();
  await assert.rejects(() => V.reconcileVortex(f.ctx, rpc.provider, pkg), /does not match/); rpc.witness.state.included = null;
  rpc.witness.state.paused = false; await assert.rejects(() => V.reconcileVortex(f.ctx, rpc.provider, pkg));
  assert.equal(rpc.primary.state.sends + rpc.witness.state.sends, 0);
});
test('synthetic mainnet lost reply retains exact intent and never resends through either RPC', async t => {
  const f = fixture(t), rpc = await online(t, f, { unknown: true }), pkg = await signed(f, await prepare(f, rpc.provider));
  const result = await V.submitVortex(f.ctx, rpc.provider, pkg, f.dir, pkg.transaction.id, 1);
  assert.equal(result.status, 'submission-outcome-unknown');
  await assert.rejects(() => V.submitVortex(f.ctx, rpc.provider, pkg, f.dir, pkg.transaction.id, 1), /intent/);
  assert.equal(rpc.primary.state.sends, 1); assert.equal(rpc.witness.state.sends, 0);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(f.dir, pkg.transaction.id.slice(2) + '.json'))).package, pkg);
});
test('installed mainnet offline dry-sign authenticates review and never opens a wallet or saved config', async t => {
  const f = fixture(t), rpc = await online(t, f), pkg = await prepare(f, rpc.provider), file = path.join(f.dir, 'tx.json'); F.writeExclusive(file, pkg);
  const args = ['vortex', 'sign', file, '--manifest', f.manifestFile, '--abi', f.abiFile, '--review', f.reviewFile, '--review-key', f.reviewKey, '--wallet', 'absent', '--vault-dir', '/does-not-exist', '--signer', X.admins[0].address, '--id', pkg.transaction.id, '--dry-run'];
  const r = spawnSync('kcli', args, { encoding: 'utf8', env: { ...process.env, HOME: f.dir }, timeout: 10000 });
  assert.equal(r.status, 0, r.stderr); assert.match(r.stdout, /"walletUnlocked": false/); assert(!fs.existsSync(path.join(f.dir, '.kcli')));
  const untrusted = spawnSync('kcli', args.filter((value, i) => i !== args.indexOf('--review-key') && i !== args.indexOf('--review-key') + 1), { encoding: 'utf8', env: { ...process.env, HOME: f.dir }, timeout: 10000 });
  assert.equal(untrusted.status, 1); assert.match(untrusted.stderr, /trusted --review-key/); assert(!untrusted.stdout.includes('Wallet password:'));
});
test('installed mainnet online dry-runs bind both reviewed RPCs and never unlock, write intent or broadcast', async t => {
  const f = fixture(t), rpc = await online(t, f), file = path.join(f.dir, 'ready.json'), out = path.join(f.dir, 'unused.json');
  const pkg = await signed(f, await prepare(f, rpc.provider)); F.writeExclusive(file, pkg);
  const argsFile = path.join(f.dir, 'args.json'); F.writeExclusive(argsFile, {});
  const binding = ['--network', 'mainnet', '--rpc', urls[0], '--corroborating-rpc', urls[1], '--contract', X.bridge.address, '--manifest', f.manifestFile, '--abi', f.abiFile, '--review', f.reviewFile, '--review-key', f.reviewKey];
  const run = argv => new Promise((resolve, reject) => {
    const child = spawn('kcli', argv, { env: { ...process.env, HOME: f.dir, NODE_OPTIONS: '--require ' + path.join(__dirname, 'fixtures/vortex-rpc-preload.cjs'), KCLI_TEST_RPC_ROUTES: JSON.stringify({ [urls[0]]: rpc.primary.provider.rpc, [urls[1]]: rpc.witness.provider.rpc }) }, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = ''; child.stdout.on('data', b => stdout += b); child.stderr.on('data', b => stderr += b); child.on('error', reject); child.on('close', status => resolve({ status, stdout, stderr }));
  });
  const prepared = await run(['vortex', 'prepare', 'pause', ...binding, '--args', argsFile, '--rc-limit', '200000000', '--out', out, '--dry-run']);
  assert.equal(prepared.status, 0, prepared.stderr); assert.match(prepared.stdout, /"walletUnlocked": false/); assert(!fs.existsSync(out));
  const journal = path.join(f.dir, 'no-journal');
  const submitted = await run(['vortex', 'submit', file, ...binding, '--journal-dir', journal, '--dry-run']);
  assert.equal(submitted.status, 0, submitted.stderr); assert.match(submitted.stdout, /"submitted": false/); assert(!fs.existsSync(journal));
  const missingPeer = await run(['vortex', 'prepare', 'pause', ...binding.filter((v, i) => i !== 4 && i !== 5), '--args', argsFile, '--rc-limit', '200000000', '--dry-run']);
  assert.equal(missingPeer.status, 1); assert.match(missingPeer.stderr, /Explicit primary/);
  assert(!fs.existsSync(path.join(f.dir, '.kcli'))); assert.equal(rpc.primary.state.sends + rpc.witness.state.sends, 0);
});
