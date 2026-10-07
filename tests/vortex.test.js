const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const { Signer, Contract, Transaction, utils } = require('koilib');
const W = require('../dist/named-wallets');
const F = require('../dist/secure-files');
const P = require('../dist/vortex-protocol');
const V = require('../dist/vortex');
const X = require('./vortex-fixture');
const password = 'synthetic-only-wallet-password';
function temp(t) { const dir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'kcli-vortex-test-')); fs.chmodSync(dir, 0o700); t.after(() => fs.rmSync(dir, { recursive: true, force: true })); return dir; }
async function signed(f, p, recovery = false) {
  for (const s of X.admins.slice(0, recovery ? 3 : 2)) p = await V.appendSignature(f.ctx, p, s, p.transaction.id, 'admin');
  return V.appendSignature(f.ctx, p, X.payer, p.transaction.id, 'payer');
}
test('strict JSON rejects duplicates, prototype keys, deep structures and unsafe numbers', () => {
  for (const input of ['{"a":1,"a":2}', '{"__proto__":{}}', '{"x":9007199254740992}', '['.repeat(26) + '0' + ']'.repeat(26), '{} trailing', '\u00a0{}']) assert.throws(() => F.strictJson(input));
});
test('wallet encryption authenticates identity, bounds KDF, and verifies passwords/address', () => {
  const vault = W.encryptNamed(X.admins[0], 'admin-a', password);
  assert.equal(W.decryptNamed(vault, 'admin-a', password).address, X.admins[0].address);
  assert.throws(() => W.decryptNamed(vault, 'admin-a', 'wrong'), /unlock failed/);
  const changed = structuredClone(vault); changed.address = X.admins[1].address; assert.throws(() => W.decryptNamed(changed, 'admin-a', password), /unlock failed/);
  changed.kdf.N *= 2; assert.throws(() => W.decryptNamed(changed, 'admin-a', password), /KDF/);
  changed.kdf.N = vault.kdf.N; changed.cipher.tag = '00'.repeat(16); assert.throws(() => W.decryptNamed(changed, 'admin-a', password), /unlock failed/);
  const mismatched = W.encryptNamed({ getAddress: () => X.admins[1].address, getPrivateKey: () => X.admins[0].getPrivateKey('wif') }, 'admin-a', password);
  assert.throws(() => W.decryptNamed(mismatched, 'admin-a', password), /address mismatch/);
  assert.throws(() => W.encryptNamed(X.admins[0], 'admin-a', 'short'), /password/);
});
test('named wallets preserve default/config and refuse overwrite, paths, symlinks and permissions', t => {
  const dir = temp(t); const legacy = path.join(dir, 'wallet.json'), config = path.join(dir, 'config.json'); fs.writeFileSync(legacy, 'old-wallet'); fs.writeFileSync(config, 'old-config');
  const store = new W.NamedWallets(path.join(dir, 'named')); store.save(X.admins[0], 'admin-a', password);
  assert.equal(store.list().length, 1); assert.equal(store.metadata('admin-a').address, X.admins[0].address);
  assert.throws(() => store.save(X.admins[1], 'admin-a', password), /exists/);
  for (const name of ['../wallet', '/absolute', 'default', 'a/b', 'Admin']) assert.throws(() => store.read(name));
  const file = store.file('admin-a'); assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  fs.chmodSync(file, 0o644); assert.throws(() => store.read('admin-a'), /0600/); fs.chmodSync(file, 0o600);
  fs.symlinkSync(file, path.join(dir, 'named', 'admin-b.json')); assert.throws(() => store.read('admin-b'), /Symlink/);
  fs.chmodSync(path.join(dir, 'named'), 0o755); assert.throws(() => store.read('admin-a'), /0700/);
  assert.equal(fs.readFileSync(legacy, 'utf8'), 'old-wallet'); assert.equal(fs.readFileSync(config, 'utf8'), 'old-config');
});
test('exclusive package writes reject existing destinations and unsafe parents', t => {
  const dir = temp(t), file = path.join(dir, 'package.json'); F.writeExclusive(file, { test: true });
  assert.throws(() => F.writeExclusive(file, {})); assert.equal(F.readSafe(file).includes('true'), true);
  assert.throws(() => F.writeExclusive(dir + '/../escape', {}), /Unsafe path/);
  const link = path.join(dir, 'link'); fs.symlinkSync(file, link); assert.throws(() => F.writeExclusive(link, {}), /Symlink/);
});
test('independent transaction ID equals SDK and refuses signed fields/body mutations', async t => {
  const f = X.fixture(temp(t)), pkg = await f.pkg(); assert.equal(P.transactionId(pkg.transaction), pkg.transaction.id);
  const review = await V.reviewPackage(f.ctx, pkg); assert.equal(review.nonce, '1'); assert.equal(review.payer, X.payer.address); assert.equal(review.manaLimit, '200000000');
  for (const mutate of [p => p.transaction.header.rc_limit = '9', p => p.transaction.header.payee = X.payer.address, p => p.transaction.operations[0].call_contract.args = 'CAE=', p => p.transaction.header.nonce = 'KAI=', p => p.transaction.hidden = true]) {
    const p = structuredClone(pkg); mutate(p); await assert.rejects(() => V.reviewPackage(f.ctx, p));
  }
});
test('pinned policy refuses release drift, public networks, role collisions and bad thresholds', t => {
  const { manifest } = X.fixture(temp(t));
  for (const mutate of [m => m.source.commit = '00'.repeat(20), m => m.network.name = 'mainnet', m => m.policy.adminThreshold = 1, m => m.policy.recoveryThreshold = 2, m => m.policy.payer = m.policy.admins[0], m => m.policy.delayMs = '60000', m => m.policy.reviewed = false]) { const m = structuredClone(manifest); mutate(m); assert.throws(() => V.validateManifest(m)); }
});
test('bridge eligibility has no permanent address veto; compatibility and network guards remain', t => {
  const dir = temp(t), { manifest, manifestFile, abiFile } = X.fixture(dir);
  manifest.contract.address = '1aqHtNRDkiAZeFtuM8fRFuurcje6eHqF8';
  assert.doesNotThrow(() => V.validateManifest(manifest));
  for (const mutate of [m => m.contract.address = 'invalid', m => m.contract.address = m.policy.payer, m => m.contract.codeSha256 = 'invalid', m => m.policy.reviewed = false, m => m.network.chainId = 'EiBZK_GGVP0H_fXVAM3j6EAuz3-B-l3ejxRSewi7qIBfSA==']) {
    const changed = structuredClone(manifest); mutate(changed); assert.throws(() => V.validateManifest(changed));
  }
  fs.writeFileSync(manifestFile, JSON.stringify(manifest));
  const local = V.loadVortex(manifestFile, abiFile);
  assert.equal(local.contract.getId(), manifest.contract.address);
  assert.throws(() => new V.VortexProvider('https://api.koinos.io'), /explicit loopback/);
  const alteredAbi = structuredClone(local.manifest); alteredAbi.contract.abiSha256 = '00'.repeat(32);
  fs.writeFileSync(manifestFile, JSON.stringify(alteredAbi));
  assert.throws(() => V.loadVortex(manifestFile, abiFile), /ABI hash/);
  manifest.network.name = 'mainnet'; fs.writeFileSync(manifestFile, JSON.stringify(manifest));
  const result = spawnSync('kcli', ['vortex', 'prepare', 'pause', '--network', 'mainnet', '--rpc', 'http://127.0.0.1:1', '--contract', manifest.contract.address, '--manifest', manifestFile, '--abi', abiFile, '--args', path.join(dir, 'absent.json'), '--rc-limit', '1', '--dry-run'], { encoding: 'utf8', env: { ...process.env, HOME: dir } });
  assert.equal(result.status, 1); assert.match(result.stderr, /fields|public network profile/);
  assert.equal(fs.existsSync(path.join(dir, '.kcli')), false);
});
test('ABI checks reject redirected entry points, incorrect types and authority', t => {
  const f = X.fixture(temp(t)); const abi = JSON.parse(f.abiText);
  for (const mutate of [a => a.methods.pause.entry_point++, a => a.methods.is_paused.read_only = false, a => a.types.nested.bridge.nested.pause_arguments.fields.expiry.type = 'uint32']) { const a = structuredClone(abi); mutate(a); assert.throws(() => P.reviewedAbi(a, 'pinned-migration')); }
});
test('reviewed adapter matches the exact candidate binary descriptor and snake-case wire encoding', async () => {
  const text = fs.readFileSync(path.join(__dirname, 'fixtures/vortex-fresh.abi.json'), 'utf8');
  assert.equal(P.sha(text), '0810d36e1130a34a8ebfc16a2bb73f58cc00a65dd102fd7a2516017b619ee234');
  const raw = JSON.parse(text);
  for (const m of Object.values(raw.methods)) { m.entry_point = Number(m['entry-point']); m.read_only = m['read-only']; }
  const reviewed = new Contract({ id: X.bridge.address, abi: P.reviewedAbi(raw, 'fresh-initializer') });
  const source = new Contract({ id: X.bridge.address, abi: raw });
  const cases = [
    ['pause', { expiry: '0', signatures: [] }, { expiry: '0', signatures: [] }],
    ['unpause', {}, {}],
    ['recover_validators', { validators: X.validators.map(s => s.address) }, { validators: X.validators.map(s => s.address) }],
    ['propose', { entryPoint: P.entryPoint('unpause'), args: '' }, { entry_point: P.entryPoint('unpause'), args: '' }],
    ['cancel', { actionHash: '0x1220' + '01'.repeat(32), expiry: '0', signatures: [] }, { action_hash: '0x1220' + '01'.repeat(32), expiry: '0', signatures: [] }],
  ];
  for (const [name, camel, snake] of cases) assert.deepEqual(await reviewed.encodeOperation({ name, args: camel }), await source.encodeOperation({ name, args: snake }));
  const changed = structuredClone(raw); changed.types = 'not a descriptor'; assert.throws(() => P.reviewedAbi(changed, 'fresh-initializer'), /descriptor/);
});
test('offline signing preserves every header, operation, ID and previous signature', async t => {
  const f = X.fixture(temp(t)), pkg = await f.pkg(); let a = await V.appendSignature(f.ctx, pkg, X.admins[0], pkg.transaction.id, 'admin');
  const initial = F.canonical({ ...pkg.transaction, signatures: [] }); a = await V.appendSignature(f.ctx, a, X.admins[1], pkg.transaction.id, 'admin');
  assert.equal(F.canonical({ ...a.transaction, signatures: [] }), initial); assert.equal(pkg.transaction.signatures.length, 0); assert.equal(a.transaction.signatures.length, 2);
  assert.equal((await V.reviewPackage(f.ctx, a)).status, 'partially-signed');
  a = await V.appendSignature(f.ctx, a, X.payer, pkg.transaction.id, 'payer'); assert.equal((await V.reviewPackage(f.ctx, a)).status, 'signature-requirements-satisfied');
});
test('duplicate, wrong requested, unknown and malformed signatures are refused', async t => {
  const f = X.fixture(temp(t)), pkg = await f.pkg(); const a = await V.appendSignature(f.ctx, pkg, X.admins[0], pkg.transaction.id, 'admin');
  await assert.rejects(() => V.appendSignature(f.ctx, a, X.admins[0], pkg.transaction.id, 'admin'), /already signed/);
  await assert.rejects(() => V.appendSignature(f.ctx, pkg, X.admins[0], '0x1220' + '00'.repeat(32), 'admin'), /exact reviewed/);
  await assert.rejects(() => V.appendSignature(f.ctx, pkg, X.payer, pkg.transaction.id, 'admin'), /requested/);
  const unknown = structuredClone(pkg); await Signer.fromSeed('kcli-disposable-attacker').signTransaction(unknown.transaction); await assert.rejects(() => V.reviewPackage(f.ctx, unknown), /unknown/);
  const doubled = structuredClone(a); doubled.transaction.signatures.push(doubled.transaction.signatures[0]); await assert.rejects(() => V.reviewPackage(f.ctx, doubled), /Duplicate/);
  const corrupt = structuredClone(a); corrupt.transaction.signatures[0] = utils.encodeBase64url(Buffer.alloc(65)); await assert.rejects(() => V.reviewPackage(f.ctx, corrupt), /signature/);
});
test('independent signatures merge only identical packages; duplicates and changed review refused', async t => {
  const f = X.fixture(temp(t)), pkg = await f.pkg(); const a = await V.appendSignature(f.ctx, pkg, X.admins[0], pkg.transaction.id, 'admin'), b = await V.appendSignature(f.ctx, pkg, X.admins[1], pkg.transaction.id, 'admin');
  const m = await V.mergePackages(f.ctx, [a, b]); assert.equal(m.transaction.signatures.length, 2);
  await assert.rejects(() => V.mergePackages(f.ctx, [a, a]), /Duplicate/); const changed = structuredClone(b); changed.snapshot.head.time = '400000001'; await assert.rejects(() => V.mergePackages(f.ctx, [a, changed]), /changed/);
});
test('recovery needs 3 admin signatures; payer never inflates either quorum', async t => {
  const f = X.fixture(temp(t)), pkg = await f.pkg('recover_validators', { validators: X.validators.map(s => s.address) });
  let a = pkg; for (const s of X.admins.slice(0, 2)) a = await V.appendSignature(f.ctx, a, s, pkg.transaction.id, 'admin');
  assert.equal((await V.reviewPackage(f.ctx, a)).required, 3); await assert.rejects(() => V.appendSignature(f.ctx, a, X.payer, a.transaction.id, 'payer'), /quorum/);
  const invalid = structuredClone(a); await X.payer.signTransaction(invalid.transaction); assert.equal((await V.reviewPackage(f.ctx, invalid)).adminSignatures, 2); assert.equal((await V.reviewPackage(f.ctx, invalid)).status, 'partially-signed');
  assert.equal((await V.reviewPackage(f.ctx, await signed(f, pkg, true))).status, 'signature-requirements-satisfied');
});
test('reviewed seven-member policy uses its selected 4/5 thresholds rather than rehearsal constants', async t => {
  const f = X.fixture(temp(t)); const extra = [4, 5, 6, 7].map(n => Signer.fromSeed('kcli-disposable-extra-admin-' + n));
  f.manifest.policy.admins = [...X.admins, ...extra].map(s => s.address); f.manifest.policy.adminThreshold = 4; f.manifest.policy.recoveryThreshold = 5;
  fs.writeFileSync(f.manifestFile, JSON.stringify(f.manifest)); const ctx = V.loadVortex(f.manifestFile, f.abiFile);
  const p = await f.pkg('recover_validators', { validators: X.validators.map(s => s.address) }); p.manifestSha256 = ctx.manifestSha256;
  p.snapshot.admins = ctx.manifest.policy.admins; Object.assign(p.snapshot.config, { adminCount: 7, adminThreshold: 4, recoveryThreshold: 5 });
  let signed = p; for (const s of [...X.admins, extra[0]]) signed = await V.appendSignature(ctx, signed, s, p.transaction.id, 'admin');
  assert.equal((await V.reviewPackage(ctx, signed)).required, 5);
  await assert.rejects(() => V.appendSignature(ctx, signed, X.payer, p.transaction.id, 'payer'), /quorum/);
  signed = await V.appendSignature(ctx, signed, extra[1], p.transaction.id, 'admin');
  assert.equal((await V.reviewPackage(ctx, await V.appendSignature(ctx, signed, X.payer, p.transaction.id, 'payer'))).status, 'signature-requirements-satisfied');
});
test('scheduled execution checks delay, expiry and epoch; validator authorities unsupported', async t => {
  const f = X.fixture(temp(t)), pkg = await f.pkg('unpause');
  for (const mutate of [p => p.snapshot.head.time = '349999999', p => p.snapshot.head.time = '436400001', p => p.snapshot.proposal.epoch = '0', p => p.snapshot.proposal.eta = '0']) { const p = structuredClone(pkg); mutate(p); await assert.rejects(() => V.reviewPackage(f.ctx, p)); }
  await assert.rejects(() => V.encodeAction(f.ctx, 'pause', { signatures: ['anything'] }), /fields/);
  await assert.rejects(() => V.encodeAction(f.ctx, 'claim', {}), /Unsupported/);
});
test('empty unpause proposal bytes round-trip without changing the exact operation or hash', async t => {
  const f = X.fixture(temp(t)); const p = await f.pkg('unpause', {}, true);
  const review = await V.reviewPackage(f.ctx, p); assert.equal(review.action.inner.name, 'unpause');
  assert.equal(review.proposal.exists, false); assert.equal(review.proposal.executionDeadline, null); assert.equal(review.proposal.earliestPossibleEta, '572800000');
  const decoded = await P.decodeExact(f.ctx.contract, p.transaction.operations[0].call_contract);
  assert.equal(decoded.args.args, ''); assert.equal(review.action.proposalHash, P.actionHash(P.entryPoint('unpause'), ''));
});
test('actual installed CLI dry signing never touches wallet, RPC, password or config', async t => {
  const dir = temp(t), f = X.fixture(dir), pkg = await f.pkg(), file = path.join(dir, 'tx.json'); F.writeExclusive(file, pkg);
  const run = spawnSync('kcli', ['vortex', 'sign', file, '--manifest', f.manifestFile, '--abi', f.abiFile, '--wallet', 'absent', '--vault-dir', '/does-not-exist', '--signer', X.admins[0].address, '--id', pkg.transaction.id, '--dry-run'], { encoding: 'utf8', env: { ...process.env, HOME: dir }, timeout: 10000 });
  assert.equal(run.status, 0, run.stderr); assert.match(run.stdout, /"walletUnlocked": false/); assert.equal(fs.existsSync(path.join(dir, '.kcli')), false);
  const noninteractive = spawnSync('kcli', ['wallets', 'create', 'admin-a', '--vault-dir', path.join(dir, 'vaults')], { encoding: 'utf8', env: { ...process.env, HOME: dir } }); assert.equal(noninteractive.status, 1); assert.match(noninteractive.stderr, /interactive terminal/);
});
test('installed signing refuses a wallet/address mismatch before the hidden prompt', async t => {
  const dir = temp(t), f = X.fixture(dir), p = await f.pkg(), file = path.join(dir, 'tx.json'); F.writeExclusive(file, p);
  const vaultDir = path.join(dir, 'wallets'); new W.NamedWallets(vaultDir).save(X.admins[1], 'admin-a', password);
  const r = spawnSync('kcli', ['vortex', 'sign', file, '--manifest', f.manifestFile, '--abi', f.abiFile, '--wallet', 'admin-a', '--vault-dir', vaultDir, '--signer', X.admins[0].address, '--id', p.transaction.id, '--out', path.join(dir, 'signed.json')], { encoding: 'utf8', env: { ...process.env, HOME: dir } });
  assert.equal(r.status, 1); assert.match(r.stderr, /does not match/); assert(!r.stdout.includes('Wallet password:')); assert(!fs.existsSync(path.join(dir, 'signed.json')));
});
function installed(argv, home) {
  return new Promise((resolve, reject) => {
    const child = spawn('kcli', argv, { env: { ...process.env, HOME: home }, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = ''; child.stdout.on('data', b => stdout += b); child.stderr.on('data', b => stderr += b); child.on('error', reject);
    child.on('close', status => resolve({ status, stdout, stderr }));
  });
}
test('installed prepare/submit dry-runs require explicit online flags and preserve legacy files', async t => {
  const dir = temp(t), f = X.fixture(dir), rpc = await X.rpcFixture(f); t.after(rpc.close);
  const legacyDir = path.join(dir, '.kcli'); fs.mkdirSync(legacyDir, { mode: 0o700 });
  for (const file of ['config.json', 'wallet.json']) fs.writeFileSync(path.join(legacyDir, file), 'untouched-legacy-sentinel', { mode: 0o600 });
  const args = path.join(dir, 'args.json'); F.writeExclusive(args, {}); const out = path.join(dir, 'unsigned.json');
  const binding = ['--manifest', f.manifestFile, '--abi', f.abiFile, '--contract', X.bridge.address];
  const missing = await installed(['vortex', 'prepare', 'pause', ...binding, '--args', args, '--rc-limit', '200000000', '--dry-run'], dir);
  assert.equal(missing.status, 1); assert.match(missing.stderr, /explicit --network and --rpc/);
  const online = [...binding, '--network', 'local', '--rpc', rpc.provider.rpc];
  const prepared = await installed(['vortex', 'prepare', 'pause', ...online, '--args', args, '--rc-limit', '200000000', '--out', out, '--dry-run'], dir);
  assert.equal(prepared.status, 0, prepared.stderr); assert.match(prepared.stdout, /"walletUnlocked": false/); assert(!fs.existsSync(out));
  const p = await signed(f, await V.prepareVortex(f.ctx, rpc.provider, await V.encodeAction(f.ctx, 'pause', {}), '200000000'));
  const file = path.join(dir, 'ready.json'); F.writeExclusive(file, p); const journal = path.join(dir, 'no-journal');
  const submitted = await installed(['vortex', 'submit', file, ...online, '--journal-dir', journal, '--dry-run'], dir);
  assert.equal(submitted.status, 0, submitted.stderr); assert.match(submitted.stdout, /"submitted": false/); assert.equal(rpc.state.sends, 0); assert(!fs.existsSync(journal));
  for (const name of ['config.json', 'wallet.json']) assert.equal(fs.readFileSync(path.join(legacyDir, name), 'utf8'), 'untouched-legacy-sentinel');
});
function terminal(home, argv, inputs) {
  const result = spawnSync('python3', [path.join(__dirname, 'vortex-pty.py')], { input: JSON.stringify({ home, argv: ['kcli', ...argv], inputs }), encoding: 'utf8', timeout: 35000 });
  assert.equal(result.status, 0, result.stderr); const response = JSON.parse(result.stdout); assert.equal(response.leaked, false); return response;
}
test('installed secure import accepts hidden synthetic WIF only and never prints it or password', t => {
  const dir = temp(t), vaultDir = path.join(dir, 'wallets'); const s = Signer.fromSeed('kcli-hidden-import-synthetic');
  const r = terminal(dir, ['wallets', 'import', 'admin-a', '--vault-dir', vaultDir], [{ prompt: 'Import WIF (hidden): ', value: s.getPrivateKey('wif') }, { prompt: 'New wallet password: ', value: password }, { prompt: 'Confirm wallet password: ', value: password }]);
  assert.equal(r.status, 0, r.stdout); assert.equal(new W.NamedWallets(vaultDir).metadata('admin-a').address, s.address);
});
test('hidden input cancellation and password mismatch fail without wallet/config writes', t => {
  const dir = temp(t), vaultDir = path.join(dir, 'wallets');
  const cancelled = terminal(dir, ['wallets', 'create', 'admin-a', '--vault-dir', vaultDir], [{ prompt: 'New wallet password: ', value: 'synthetic-partial' + '\x03' + 'queued-tail' }]);
  assert.equal(cancelled.status, 1); assert.equal(fs.existsSync(vaultDir), false); assert(!cancelled.stdout.includes('synthetic-partial')); assert(!cancelled.stdout.includes('queued-tail'));
  const mismatch = terminal(dir, ['wallets', 'create', 'admin-a', '--vault-dir', vaultDir], [{ prompt: 'New wallet password: ', value: password }, { prompt: 'Confirm wallet password: ', value: 'different-synthetic-password' }]);
  assert.equal(mismatch.status, 1); assert.equal(fs.existsSync(vaultDir), false); assert.equal(fs.existsSync(path.join(dir, '.kcli')), false);
});
test('malicious signing result that uses a different identity cannot replace or append signatures', async t => {
  const f = X.fixture(temp(t)), pkg = await f.pkg();
  const wrong = { getAddress: () => X.admins[0].address, signHash: bytes => X.admins[1].signHash(bytes) };
  await assert.rejects(() => V.appendSignature(f.ctx, pkg, wrong, pkg.transaction.id, 'admin'), /replaced or lost/);
  assert.equal(pkg.transaction.signatures.length, 0);
});
test('online preparation is unsigned and refuses wrong chain/code/ABI/member/Mana', async t => {
  const f = X.fixture(temp(t)), rpc = await X.rpcFixture(f); t.after(rpc.close); const op = await V.encodeAction(f.ctx, 'pause', {});
  const pkg = await V.prepareVortex(f.ctx, rpc.provider, op, '200000000'); assert.equal(pkg.transaction.signatures.length, 0); assert.equal(rpc.state.sends, 0);
  for (const [key, value] of [['chainId', utils.encodeBase64url(Buffer.alloc(34))], ['code', Buffer.from('wrong')], ['abiText', '{}'], ['admins', [X.admins[0].address]], ['mana', '1']]) {
    const prev = rpc.state[key]; rpc.state[key] = value; await assert.rejects(() => V.prepareVortex(f.ctx, rpc.provider, op, '200000000')); rpc.state[key] = prev;
  }
});
test('submission preflight rejects missing quorum, stale nonce, changed epoch and proposal', async t => {
  const f = X.fixture(temp(t)), rpc = await X.rpcFixture(f); t.after(rpc.close); const pkg = await V.prepareVortex(f.ctx, rpc.provider, await V.encodeAction(f.ctx, 'pause', {}), '200000000');
  await assert.rejects(() => V.preflightVortex(f.ctx, rpc.provider, pkg), /quorum/); const p = await signed(f, pkg);
  rpc.state.nonce = 'KAE='; await assert.rejects(() => V.preflightVortex(f.ctx, rpc.provider, p), /nonce/); rpc.state.nonce = 'KAA=';
  rpc.state.config.epoch = '2'; await assert.rejects(() => V.preflightVortex(f.ctx, rpc.provider, p), /stale/); assert.equal(rpc.state.sends, 0);
});
test('fresh submission state catches execution-window expiry and never submits', async t => {
  const f = X.fixture(temp(t)); const p = await f.pkg('unpause'); const rpc = await X.rpcFixture(f, { paused: true, proposal: { eta: '350000000', nonce: '1', epoch: '1', kind: 0 } }); t.after(rpc.close);
  const ready = await signed(f, p); await V.preflightVortex(f.ctx, rpc.provider, ready);
  rpc.state.time = '436400001'; await assert.rejects(() => V.preflightVortex(f.ctx, rpc.provider, ready), /expired/); assert.equal(rpc.state.sends, 0);
});
test('submission response is not inclusion/finality; reconciliation verifies actual resulting state', async t => {
  const dir = temp(t), f = X.fixture(dir), rpc = await X.rpcFixture(f); t.after(rpc.close);
  const pkg = await signed(f, await V.prepareVortex(f.ctx, rpc.provider, await V.encodeAction(f.ctx, 'pause', {}), '200000000'));
  const result = await V.submitVortex(f.ctx, rpc.provider, pkg, dir, pkg.transaction.id, 1); assert.equal(result.status, 'included-successfully'); assert.equal(rpc.state.sends, 1);
  rpc.state.irreversible = true; assert.equal((await V.reconcileVortex(f.ctx, rpc.provider, pkg)).status, 'irreversible-and-state-verified');
  rpc.state.paused = false; await assert.rejects(() => V.reconcileVortex(f.ctx, rpc.provider, pkg), /result/);
});
test('canonical inclusion requires the exact body, signature set and receipt, not just a reported ID', async t => {
  const dir = temp(t), f = X.fixture(dir), rpc = await X.rpcFixture(f); t.after(rpc.close);
  const p = await signed(f, await V.prepareVortex(f.ctx, rpc.provider, await V.encodeAction(f.ctx, 'pause', {}), '200000000'));
  await V.submitVortex(f.ctx, rpc.provider, p, dir, p.transaction.id, 1); rpc.state.irreversible = true;
  rpc.state.included = structuredClone(p.transaction); rpc.state.included.header.rc_limit = '200000001'; await assert.rejects(() => V.reconcileVortex(f.ctx, rpc.provider, p), /does not match/);
  rpc.state.included = structuredClone(p.transaction); rpc.state.included.signatures.pop(); await assert.rejects(() => V.reconcileVortex(f.ctx, rpc.provider, p), /does not match/);
  rpc.state.included = null; rpc.state.missingReceipt = true; await assert.rejects(() => V.reconcileVortex(f.ctx, rpc.provider, p), /does not match/);
  rpc.state.missingReceipt = false; rpc.state.fork = true; assert.equal((await V.reconcileVortex(f.ctx, rpc.provider, p)).status, 'submission-outcome-unknown');
  rpc.state.fork = false; assert.equal((await V.reconcileVortex(f.ctx, rpc.provider, p)).status, 'irreversible-and-state-verified'); assert.equal(rpc.state.sends, 1);
});
test('uncertain submission has durable exact intent and is never automatically sent again', async t => {
  const dir = temp(t), f = X.fixture(dir), rpc = await X.rpcFixture(f, { unknown: true }); t.after(rpc.close);
  const pkg = await signed(f, await V.prepareVortex(f.ctx, rpc.provider, await V.encodeAction(f.ctx, 'pause', {}), '200000000'));
  const result = await V.submitVortex(f.ctx, rpc.provider, pkg, dir, pkg.transaction.id, 1); assert.equal(result.status, 'submission-outcome-unknown');
  await assert.rejects(() => V.submitVortex(f.ctx, rpc.provider, pkg, dir, pkg.transaction.id, 1), /intent/); assert.equal(rpc.state.sends, 1);
  const intent = JSON.parse(fs.readFileSync(path.join(dir, pkg.transaction.id.slice(2) + '.json'))); assert.deepEqual(intent.package.transaction, pkg.transaction);
  rpc.state.paused = true; rpc.state.config.pauseNonce = '1'; rpc.state.irreversible = true;
  assert.equal((await V.reconcileVortex(f.ctx, rpc.provider, pkg)).status, 'irreversible-and-state-verified'); assert.equal(rpc.state.sends, 1);
});
test('reverted receipt and unavailable RPC never report completed; transport messages are secret safe', async t => {
  const dir = temp(t), f = X.fixture(dir), rpc = await X.rpcFixture(f, { reverted: true }); t.after(rpc.close);
  const pkg = await signed(f, await V.prepareVortex(f.ctx, rpc.provider, await V.encodeAction(f.ctx, 'pause', {}), '200000000'));
  assert.equal((await V.submitVortex(f.ctx, rpc.provider, pkg, dir, pkg.transaction.id, 1)).status, 'reverted');
  assert.equal((await V.reconcileVortex(f.ctx, rpc.provider, pkg)).status, 'reverted');
  rpc.state.failure = 'chain.get_chain_id'; await assert.rejects(() => V.chainBinding(f.ctx, rpc.provider), error => !error.message.includes('sensitive'));
  assert.throws(() => new V.VortexProvider('https://api.koinos.io'), /loopback/);
});
