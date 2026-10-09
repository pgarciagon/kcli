const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const http = require('node:http');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { Signer, Transaction, utils } = require('koilib');
const W = require('../dist/named-wallets');
const VP = require('../dist/vortex-protocol');
const MP = require('../dist/multisig-protocol');
const MN = require('../dist/multisig-network');
const M = require('../dist/multisig');
const X = require('./multisig-fixture');
const password = 'synthetic-only-wallet-password';
function temp(t) {
  const dir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'kcli-multisig-test-')); fs.chmodSync(dir, 0o700);
  // The submission journal lives under ~/.kcli: every test gets its own HOME.
  const home = process.env.HOME; process.env.HOME = dir;
  t.after(() => { process.env.HOME = home; fs.rmSync(dir, { recursive: true, force: true }); }); return dir;
}
const kcli = (home, argv, env = {}) => spawnSync('kcli', argv, { encoding: 'utf8', env: { ...process.env, HOME: home, ...env }, timeout: 60000 });
const noNetwork = path.join(__dirname, 'fixtures', 'no-network.cjs');

// ---------------------------------------------------------------------------------------------- protocol
test('amounts are exact decimal strings; floats, exponents, signs, 9 decimals, zero and overflow refuse', () => {
  assert.equal(MP.parseAmount('1'), 100000000n); assert.equal(MP.parseAmount('0.00000001'), 1n); assert.equal(MP.parseAmount('123.45'), 12345000000n);
  assert.equal(MP.formatAmount(12345000000n), '123.45'); assert.equal(MP.formatAmount(1n), '0.00000001'); assert.equal(MP.formatAmount(100000000n), '1');
  for (const bad of ['0', '0.0', '-1', '+1', '1e3', '1.000000001', '.5', '5.', '01', ' 1', '1 ', '0x10', '1,5', '1844674407370.95516160', '999999999999.99999999']) assert.throws(() => MP.parseAmount(bad), undefined, bad);
});
test('client policy rules equal the contract rules for every owner count and threshold', () => {
  const contractRule = (n, t) => n >= 3 && n <= 15 && t >= 2 && t > Math.floor(n / 2) && t < n;
  for (let n = 1; n <= 16; n++) {
    const list = Array.from({ length: n }, (_, i) => X.bySeed('rule-' + n + '-' + i).address).sort(MP.compareAddresses);
    for (let t = 0; t <= n + 1; t++) {
      let ok = true; try { MP.validatePolicy(list, t, X.treasury.address); } catch { ok = false; }
      assert.equal(ok, contractRule(n, t), `n=${n} t=${t}`);
    }
  }
  const three = X.owners.slice(0, 3).map(s => s.address);
  assert.throws(() => MP.validatePolicy([...three].reverse(), 2, X.treasury.address), /ascending/);
  assert.throws(() => MP.validatePolicy([three[0], three[0], three[1]], 2, X.treasury.address), /ascending/);
  assert.throws(() => MP.validatePolicy([...three.slice(0, 2), X.treasury.address].sort(MP.compareAddresses), 2, X.treasury.address), /own owner/);
  assert.throws(() => MP.canonicalOwners([three[0], three[0], three[1]]), /Duplicate/);
  assert.deepEqual(MP.canonicalOwners([...three].reverse()), [...three].sort(MP.compareAddresses));
  // Byte order, not string order: an address starting with "11" sorts first.
  let lead; for (let i = 0; !lead; i++) { const s = X.bySeed('lead-' + i); if (s.address.startsWith('11')) lead = s.address; }
  assert.equal(MP.canonicalOwners([three[0], lead, three[1]])[0], lead);
});
test('independent bootstrap ID equals the SDK and refuses any flag, payee or extra-operation change', async () => {
  const op = { upload_contract: { contract_id: X.treasury.address, bytecode: utils.encodeBase64url(X.code), abi: '{"methods":{}}', authorizes_call_contract: true, authorizes_transaction_application: true, authorizes_upload_contract: true } };
  const tx = await Transaction.prepareTransaction({ header: { chain_id: X.chainId, rc_limit: '500000000', nonce: utils.encodeBase64url(Buffer.from([40, 1])), payer: X.treasury.address }, operations: [op], signatures: [] });
  assert.equal(MP.deployTransactionId(tx), tx.id);
  for (const mutate of [t => t.operations[0].upload_contract.authorizes_upload_contract = false, t => t.header.payee = X.outsider.address, t => t.operations.push(structuredClone(t.operations[0])), t => t.operations[0].upload_contract.abi = '{}', t => t.header.rc_limit = '1']) {
    const t = structuredClone(tx); mutate(t); let id = null; try { id = MP.deployTransactionId(t); } catch { /* refused */ }
    assert.notEqual(id, tx.id, 'a mutated bootstrap never keeps the reviewed ID');
  }
});

// ------------------------------------------------------------------------------------------ manifest + review
test('manifests: template, KOIN binding, public chain IDs and Mainnet attestation fail closed', t => {
  const dir = temp(t); const base = X.manifestFor();
  for (const mutate of [m => m.treasury.templateVersion = '2.0.0', m => m.network.chainId = MN.TESTNET_CHAINS?.[0] || 'EiAIKVvm6-V2qmsmUvPJy09vCCLbtn9lHFpwrJbcTIEWRQ==', m => m.policy.threshold = 5, m => m.policy.owners = [...m.policy.owners].reverse(), m => m.token.symbol = 'VHP', m => m.hidden = 1, m => m.network.name = 'testnet', m => m.policy.owners = [...m.policy.owners.slice(0, 4), m.treasury.address].sort(MP.compareAddresses)]) {
    const m = structuredClone(base); mutate(m); assert.throws(() => M.validateManifest(m));
  }
  const main = structuredClone(base); main.network = { name: 'mainnet', chainId: 'EiBZK_GGVP0H_fXVAM3j6EAuz3-B-l3ejxRSewi7qIBfSA==', rpcs: [{ url: 'https://a.example-rpc.org/', operator: 'a-op' }, { url: 'https://b.other-rpc.net/', operator: 'b-op' }] }; main.token.contract = MN.PUBLIC_KOIN.mainnet;
  const file = path.join(dir, 'mainnet.json'); fs.writeFileSync(file, JSON.stringify(main), { mode: 0o600 });
  assert.throws(() => M.loadManifest(file), /review/);
  // A valid Ed25519 attestation of the exact manifest under the manifest domain loads; a bootstrap-domain one does not.
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519'); const der = publicKey.export({ type: 'spki', format: 'der' });
  const digest = VP.sha(fs.readFileSync(file, 'utf8'));
  const attest = (kind, domain) => { const f = path.join(dir, kind + '.json'); fs.writeFileSync(f, JSON.stringify({ schema: 1, kind, manifestSha256: digest, publicKey: utils.encodeBase64url(der), signature: utils.encodeBase64url(crypto.sign(null, Buffer.from(domain + digest), privateKey)) }), { mode: 0o600 }); return f; };
  const good = attest('kcli-multisig-manifest-review', 'kcli-multisig-manifest-v1\n'), wrong = attest('kcli-multisig-bootstrap-review', 'kcli-multisig-bootstrap-v1\n');
  assert.equal(M.loadManifest(file, good, VP.sha(der)).profile, 'mainnet');
  assert.throws(() => M.loadManifest(file, wrong, VP.sha(der)));
  assert.throws(() => M.loadManifest(file, good, '00'.repeat(32)), /fingerprint/);
});
test('package review recomputes the ID and refuses every signed-field, envelope or binding mutation', async t => {
  const f = X.fixture(temp(t)); const pkg = await f.pkg();
  const review = await M.reviewPackage(f.ctx, pkg);
  assert.equal(review.action.kind, 'transfer'); assert.equal(review.action.amount, '1.5'); assert.equal(review.action.raw, '150000000'); assert.equal(review.status, 'prepared'); assert.equal(review.note.signed, false);
  for (const mutate of [p => p.transaction.header.rc_limit = '9', p => p.transaction.header.payee = X.outsider.address, p => p.transaction.header.nonce = 'KAM=', p => p.transaction.hidden = 1, p => p.manifestSha256 = '00'.repeat(32), p => p.snapshot.policyVersion = '1', p => p.snapshot.nonce = '5', p => p.kind = 'kcli-multisig-deploy', p => p.note = 'bad\nnote']) {
    const p = structuredClone(pkg); mutate(p); await assert.rejects(() => M.reviewPackage(f.ctx, p));
  }
});
test('only canonical KOIN transfers from the treasury and valid set_policy calls are reviewable', async t => {
  const f = X.fixture(temp(t)); const { Contract } = require('koilib');
  const koin = new Contract({ id: X.koin, abi: MP.KOIN_ABI }), T = MP.TREASURY_ABI;
  const transfer = async args => (await koin.encodeOperation({ name: 'transfer', args })).call_contract;
  const ok = await transfer({ from: X.treasury.address, to: X.recipient, value: '5' });
  assert.equal((await MP.reviewOperation(ok, X.treasury.address, X.koin)).kind, 'transfer');
  const cases = [
    await transfer({ from: X.treasury.address, to: X.recipient, value: '5', memo: 'invoice' }),
    await transfer({ from: X.outsider.address, to: X.recipient, value: '5' }),
    await transfer({ from: X.treasury.address, to: X.treasury.address, value: '5' }),
    { ...ok, args: utils.encodeBase64url(Buffer.concat([Buffer.from(utils.decodeBase64url(ok.args)), Buffer.from([0x48, 1])])) },
    { ...ok, entry_point: MP.entryPoint('approve') }, { ...ok, entry_point: MP.entryPoint('burn') },
    { ...ok, contract_id: X.outsider.address },
    (await new Contract({ id: X.treasury.address, abi: T }).encodeOperation({ name: 'set_policy', args: { owners: X.owners.slice(0, 3).map(s => s.address).sort(MP.compareAddresses), threshold: 1 } })).call_contract,
  ];
  for (const call of cases) await assert.rejects(() => MP.reviewOperation(call, X.treasury.address, X.koin));
  const policy = await f.pkg('policy'); assert.equal((await M.reviewPackage(f.ctx, policy)).action.kind, 'policy');
});
test('signatures: distinct current owners only, exact ID, body unchanged, quorum per signer subset', async t => {
  const f = X.fixture(temp(t)); const pkg = await f.pkg();
  await assert.rejects(() => M.appendSignature(f.ctx, pkg, X.owners[0], '0x1220' + '00'.repeat(32)), /exact reviewed/);
  await assert.rejects(() => M.appendSignature(f.ctx, pkg, X.outsider, pkg.transaction.id), /not a current owner/);
  await assert.rejects(() => M.appendSignature(f.ctx, pkg, X.treasury, pkg.transaction.id), /not a current owner/);
  const one = await M.appendSignature(f.ctx, pkg, X.owners[0], pkg.transaction.id);
  await assert.rejects(() => M.appendSignature(f.ctx, one, X.owners[0], pkg.transaction.id), /already signed/);
  const dup = structuredClone(one); dup.transaction.signatures.push(dup.transaction.signatures[0]); await assert.rejects(() => M.reviewPackage(f.ctx, dup), /Duplicate/);
  const stranger = structuredClone(one); stranger.transaction.signatures.push(utils.encodeBase64url(await X.outsider.signHash(Buffer.from(pkg.transaction.id.slice(6), 'hex')))); await assert.rejects(() => M.reviewPackage(f.ctx, stranger), /current owner/);
  const high = structuredClone(one); const b = Buffer.from(utils.decodeBase64url(high.transaction.signatures[0])); const n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const s = BigInt('0x' + b.subarray(33).toString('hex')); high.transaction.signatures[0] = utils.encodeBase64url(Buffer.concat([Buffer.from([((b[0] - 31) ^ 1) + 31]), b.subarray(1, 33), Buffer.from((n - s).toString(16).padStart(64, '0'), 'hex')]));
  await assert.rejects(() => M.reviewPackage(f.ctx, high), /noncanonical/);
  for (let mask = 0; mask < 32; mask++) {
    const set = X.owners.filter((_, i) => mask & (1 << i)); const p = await X.signedBy(f, pkg, set);
    assert.equal((await M.reviewPackage(f.ctx, p)).status, set.length >= 3 ? 'quorum-ready' : set.length ? 'partial' : 'prepared');
  }
});
test('merge: same body only, deterministic owner order, conflicting identities refuse', async t => {
  const f = X.fixture(temp(t)); const pkg = await f.pkg();
  const a = await X.signedBy(f, pkg, [X.owners[2]]), b = await X.signedBy(f, pkg, [X.owners[0]]), c = await X.signedBy(f, pkg, [X.owners[4], X.owners[1]]);
  const m1 = await M.mergePackages(f.ctx, [a, b, c]), m2 = await M.mergePackages(f.ctx, [c, a, b]);
  assert.deepEqual(m1, m2); assert.equal((await M.reviewPackage(f.ctx, m1)).status, 'quorum-ready');
  assert.deepEqual((await M.reviewPackage(f.ctx, m1)).signers, [0, 1, 2, 4].map(i => X.owners[i].address));
  const other = await X.signedBy(f, await f.pkg('transfer', { raw: 7n }), [X.owners[0]]); await assert.rejects(() => M.mergePackages(f.ctx, [a, other]), /different/);
  const noted = structuredClone(b); noted.note = 'changed'; await assert.rejects(() => M.mergePackages(f.ctx, [a, noted]), /different/);
});

// --------------------------------------------------------------------------------------------- installed CLI
test('installed CLI: offline inspect/sign/merge never touch the network; wrong wallet refused before unlock', t => {
  const home = temp(t); const vault = path.join(home, 'vault'); const store = new W.NamedWallets(vault);
  for (const [i, s] of X.owners.entries()) store.save(s, 'member-' + i, password);
  const f = X.fixture(home); return (async () => {
    const pkgFile = path.join(home, 'payment.json'); fs.writeFileSync(pkgFile, JSON.stringify(await f.pkg()), { mode: 0o600 });
    const env = { NODE_OPTIONS: '--require ' + noNetwork };
    const inspected = kcli(home, ['multisig', 'inspect', pkgFile, '--manifest', f.manifestFile], env);
    assert.equal(inspected.status, 0, inspected.stderr); const review = JSON.parse(inspected.stdout); assert.equal(review.action.amount, '1.5');
    const dry = kcli(home, ['multisig', 'sign', pkgFile, '--manifest', f.manifestFile, '--wallet', 'member-0', '--signer', X.owners[0].address, '--id', review.id, '--vault-dir', vault, '--dry-run'], env);
    assert.equal(dry.status, 0, dry.stderr); assert.match(dry.stdout, /"walletUnlocked": false/);
    const wrong = kcli(home, ['multisig', 'sign', pkgFile, '--manifest', f.manifestFile, '--wallet', 'member-1', '--signer', X.owners[0].address, '--id', review.id, '--vault-dir', vault, '--out', path.join(home, 'x.json')], env);
    assert.equal(wrong.status, 1); assert.match(wrong.stderr, /does not match the requested signer/); assert.doesNotMatch(wrong.stdout + wrong.stderr, /password/i);
    const outsiderSign = kcli(home, ['multisig', 'sign', pkgFile, '--manifest', f.manifestFile, '--wallet', 'member-0', '--signer', X.outsider.address, '--id', review.id, '--vault-dir', vault, '--out', path.join(home, 'y.json')], env);
    assert.equal(outsiderSign.status, 1); assert.match(outsiderSign.stderr, /not a current owner/);
    // Hidden PTY password only; the secret never appears in output.
    const signedFiles = [];
    for (const i of [0, 1, 2]) {
      const out = path.join(home, `signed-${i}.json`); signedFiles.push(out);
      const r = spawnSync('python3', [path.join(__dirname, 'vortex-pty.py')], { input: JSON.stringify({ home, argv: ['kcli', 'multisig', 'sign', pkgFile, '--manifest', f.manifestFile, '--wallet', 'member-' + i, '--signer', X.owners[i].address, '--id', review.id, '--vault-dir', vault, '--out', out], inputs: [{ prompt: 'Wallet password: ', value: password }] }), encoding: 'utf8', timeout: 60000, env: { ...process.env, NODE_OPTIONS: '--require ' + noNetwork } });
      const reply = JSON.parse(r.stdout); assert.equal(reply.status, 0, reply.stdout); assert.equal(reply.leaked, false);
    }
    const again = kcli(home, ['multisig', 'sign', pkgFile, '--manifest', f.manifestFile, '--wallet', 'member-0', '--signer', X.owners[0].address, '--id', review.id, '--vault-dir', vault, '--out', signedFiles[0]], env);
    assert.equal(again.status, 1); // never overwrites
    const merged = path.join(home, 'approved.json');
    const m = kcli(home, ['multisig', 'merge', ...signedFiles, '--manifest', f.manifestFile, '--out', merged], env);
    assert.equal(m.status, 0, m.stderr); assert.equal(JSON.parse(m.stdout).status, 'quorum-ready');
    assert.equal(JSON.parse(fs.readFileSync(pkgFile, 'utf8')).transaction.signatures.length, 0, 'inputs never modified');
    const online = kcli(home, ['multisig', 'submit', merged, '--manifest', f.manifestFile, '--dry-run']);
    assert.equal(online.status, 1); assert.match(online.stderr, /explicit --network and --rpc/);
  })();
});

// ------------------------------------------------------------------------------------------- online (simulator)
test('info and prepare verify code, flags, policy, allowances and Mana before anything is written', async t => {
  const f = X.fixture(temp(t)); const rpc = await X.rpcFixture(f); t.after(rpc.close);
  let p = rpc.provider(); const info = await M.treasuryInfo(f.ctx, p); p.close();
  assert.equal(info.nonce, '1'); assert.equal(info.policy.version, '0'); assert.equal(info.allowances, 0);
  const op = await M.transferOperation(f.ctx, X.recipient, 100000000n);
  p = rpc.provider(); const pkg = await M.prepareAction(f.ctx, p, op, '10000000', 'invoice 7'); p.close();
  assert.equal((await M.reviewPackage(f.ctx, pkg)).nonce, '2'); assert.equal(pkg.note, 'invoice 7');
  const refusals = [[{ allowances: [{ spender: X.outsider.address, value: '1' }] }, /allowances/], [{ code: Buffer.from('other') }, /code/], [{ authority: { upload: false } }, /flags/],
    [{ policy: { owners: X.owners.slice(0, 3).map(s => s.address), threshold: 2, version: '1' } }, /policy/], [{ mana: '100000000' }, /Mana/], [{ balance: '10' }, /balance/], [{ chainId: X.chainId.replace('E', 'F') }, /chain/]];
  for (const [state, pattern] of refusals) {
    const r = await X.rpcFixture(f, state); const q = r.provider();
    await assert.rejects(() => M.prepareAction(f.ctx, q, op, '10000000', null), pattern); q.close(); await r.close();
  }
});
test('submit: fresh preflight, canonical journal + nonce lock before one send, never resent, reconcile verifies the event', async t => {
  const dir = temp(t); const f = X.fixture(dir);
  const pkg = await X.signedBy(f, await f.pkg(), X.owners.slice(0, 3));
  let rpc = await X.rpcFixture(f, { nonce: 'KAI=' }); let p = rpc.provider();
  await assert.rejects(() => M.preflight(f.ctx, p, pkg), /stale or already used/); p.close(); await rpc.close();
  const partial = await X.signedBy(f, await f.pkg(), X.owners.slice(0, 2));
  rpc = await X.rpcFixture(f); p = rpc.provider(); await assert.rejects(() => M.preflight(f.ctx, p, partial), /Missing owner approvals/);
  await assert.rejects(() => M.submit(f.ctx, p, pkg, '0x1220' + '00'.repeat(32), 1000), /exact transaction ID/); assert.equal(rpc.state.sends, 0); p.close(); await rpc.close();
  rpc = await X.rpcFixture(f, { unknown: 'lost' }); p = rpc.provider();
  const unknown = await M.submit(f.ctx, p, pkg, pkg.transaction.id, 1000); p.close();
  assert.equal(unknown.status, 'submitted-unconfirmed'); assert.equal(rpc.state.sends, 1);
  const journal = M.journalDirectory(X.chainId, X.treasury.address);
  assert(fs.existsSync(path.join(journal, pkg.transaction.id.slice(2) + '.json')) && fs.existsSync(path.join(journal, 'nonce-2.json')), 'intent + nonce lock written before send');
  assert.equal(fs.statSync(journal).mode & 0o777, 0o700);
  p = rpc.provider(); await assert.rejects(() => M.submit(f.ctx, p, pkg, pkg.transaction.id, 1000), /intent/); p.close();
  // A different transaction for the same treasury nonce cannot be sent from this machine either.
  const other = await X.signedBy(f, await f.pkg('transfer', { raw: 9n }), X.owners.slice(0, 3));
  p = rpc.provider(); await assert.rejects(() => M.submit(f.ctx, p, other, other.transaction.id, 1000), /treasury nonce/); p.close();
  assert.equal(rpc.state.sends, 1); await rpc.close();
  // Accepted, then the connection dropped: inclusion is found by reconciliation, never by resending.
  const home2 = path.join(dir, 'h2'); fs.mkdirSync(home2, { mode: 0o700 }); process.env.HOME = home2;
  rpc = await X.rpcFixture(f, { unknown: 'accepted' }); p = rpc.provider();
  const accepted = await M.submit(f.ctx, p, pkg, pkg.transaction.id, 1000); p.close();
  assert.equal(accepted.status, 'included'); assert.equal(rpc.state.sends, 1); await rpc.close();
  const home3 = path.join(dir, 'h3'); fs.mkdirSync(home3, { mode: 0o700 }); process.env.HOME = home3;
  rpc = await X.rpcFixture(f, { irreversible: true }); p = rpc.provider();
  const done = await M.submit(f.ctx, p, pkg, pkg.transaction.id, 5000); p.close();
  assert.equal(done.status, 'irreversible-and-verified'); assert.equal(done.transferEvent.to, X.recipient); assert.equal(rpc.state.sends, 1);
  rpc.state.eventTo = X.outsider.address; p = rpc.provider(); await assert.rejects(() => M.reconcile(f.ctx, p, pkg), /event/); p.close();
  rpc.state.eventTo = undefined; rpc.state.irreversible = false; p = rpc.provider(); assert.equal((await M.reconcile(f.ctx, p, pkg)).status, 'included'); p.close();
  rpc.state.reverted = true; p = rpc.provider(); assert.equal((await M.reconcile(f.ctx, p, pkg)).status, 'included-reverted', 'a reversible revert is not final'); p.close();
  rpc.state.irreversible = true; p = rpc.provider(); assert.equal((await M.reconcile(f.ctx, p, pkg)).status, 'reverted'); p.close();
  rpc.state.reverted = false; rpc.state.fork = true; p = rpc.provider(); assert.equal((await M.reconcile(f.ctx, p, pkg)).status, 'unknown'); p.close(); await rpc.close();
});
test('reconcile accepts any valid quorum subset of the package signatures (same ID) and refuses a non-quorum one', async t => {
  const f = X.fixture(temp(t)); const all = await X.signedBy(f, await f.pkg(), X.owners);
  const subset = structuredClone(all.transaction); subset.signatures = subset.signatures.slice(1, 4);
  const rpc = await X.rpcFixture(f, { irreversible: true, tx: all.transaction, included: subset }); t.after(rpc.close);
  let p = rpc.provider(); assert.equal((await M.reconcile(f.ctx, p, all)).status, 'irreversible-and-verified'); p.close();
  rpc.state.included = { ...subset, signatures: subset.signatures.slice(0, 2) };
  p = rpc.provider(); await assert.rejects(() => M.reconcile(f.ctx, p, all), /quorum/); p.close();
});
test('policy reconciliation verifies the exact new policy and returns the next manifest snapshot', async t => {
  const f = X.fixture(temp(t)); const next = X.owners.slice(1, 4).map(s => s.address).sort(MP.compareAddresses);
  const pkg = await X.signedBy(f, await f.pkg('policy', { owners: next, threshold: 2 }), X.owners.slice(0, 3));
  const rpc = await X.rpcFixture(f, { irreversible: true }); t.after(rpc.close);
  rpc.state.tx = pkg.transaction; rpc.state.policy = { owners: next, threshold: 2, version: '1' };
  const p = rpc.provider(); const r = await M.reconcile(f.ctx, p, pkg); p.close();
  assert.equal(r.status, 'irreversible-and-verified'); assert.deepEqual(r.manifest.policy, { owners: next, threshold: 2, version: '1' });
  assert.equal(M.validateManifest(r.manifest), 'local');
  rpc.state.policy = { owners: next, threshold: 2, version: '2' }; const q = rpc.provider(); assert.equal((await M.reconcile(f.ctx, q, pkg)).status, 'unknown'); q.close();
});

test('read windows: KOIN system-space balance writes in advancing blocks are not treasury changes; protected ones are', async t => {
  const f = X.fixture(temp(t)); const b = a => Buffer.from(utils.decodeBase58(a)); const e = buf => utils.encodeBase64url(buf);
  const zone = e(b(X.treasury.address)), koinKey = e(b(X.koin)), other = e(b(X.outsider.address));
  // KOIN's storage zone is not its contract ID (Mainnet keeps the old KOIN address as zone): any non-kernel system zone.
  const koinZone = e(b(X.bySeed('legacy-koin-zone').address));
  const d = (system, zoneValue, id, key = '') => ({ object_space: { ...(system && { system: true }), ...(zoneValue && { zone: zoneValue }), ...(id && { id }) }, key });
  const P = delta => MN.protectedDelta(delta, X.treasury.address, X.koin);
  assert.equal(P(d(true, koinZone, 1, other)), false, 'KOIN balance of another account (written every block)');
  assert.equal(P(d(true, koinZone, 1, zone)), true, 'KOIN balance of the treasury');
  assert.equal(P(d(true, koinZone, 2, e(Buffer.concat([b(X.treasury.address), b(X.outsider.address)])))), true, 'KOIN allowance owned by the treasury');
  assert.equal(P(d(true, koinZone, 2, e(Buffer.concat([b(X.outsider.address), b(X.treasury.address)])))), false, 'allowance where the treasury is only the spender');
  assert.equal(P(d(true, '', 1, 'AA==')), true, 'system-call dispatch');
  assert.equal(P(d(true, '', 4, zone)), true, 'treasury nonce');
  assert.equal(P(d(true, '', 4, other)), false, 'another account nonce');
  assert.equal(P(d(true, '', 3, zone)), true, 'treasury metadata');
  assert.equal(P(d(true, '', 2, koinKey)), true, 'KOIN bytecode');
  assert.equal(P(d(false, zone, 0)), true, 'treasury storage');
  assert.equal(P(d(false, koinKey, 0)), false, 'other contract storage');
  let rpc = await X.rpcFixture(f, { advancing: true, deltas: [d(true, koinZone, 1, other), d(true, '', 4, other)] }); let p = rpc.provider();
  assert.equal((await M.treasuryInfo(f.ctx, p)).policy.version, '0'); p.close(); await rpc.close();
  for (const delta of [d(false, zone, 0), d(true, koinZone, 1, zone), d(true, '', 1, 'AA==')]) {
    rpc = await X.rpcFixture(f, { advancing: true, deltas: [delta] }); p = rpc.provider();
    await assert.rejects(() => M.treasuryInfo(f.ctx, p), /changed during reads/); p.close(); await rpc.close();
  }
});

// --------------------------------------------------------------------------------------------- transport
test('transport: at most two sockets/active requests, bounded read retries, writes never retried, deadline', async t => {
  let active = 0, peak = 0, hits = 0, mode = 'ok'; const sockets = new Set();
  const server = http.createServer(async (req, res) => {
    sockets.add(req.socket); hits++; active++; peak = Math.max(peak, active);
    const chunks = []; for await (const c of req) chunks.push(c); const j = JSON.parse(Buffer.concat(chunks));
    await new Promise(r => setTimeout(r, 30)); active--;
    if (mode === '503') { res.writeHead(503); res.end(); return; }
    if (mode === 'huge') { res.end(JSON.stringify({ jsonrpc: '2.0', id: j.id, result: 'x'.repeat(1100000) })); return; }
    if (mode === 'hang') return;
    if (mode === 'trickle') { res.writeHead(200); const timer = setInterval(() => { if (res.destroyed) clearInterval(timer); else res.write(' '); }, 100); res.on('close', () => clearInterval(timer)); return; }
    res.end(JSON.stringify({ jsonrpc: '2.0', id: j.id, result: { chain_id: X.chainId } }));
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r)); t.after(() => { server.closeAllConnections?.(); server.close(); });
  const url = 'http://127.0.0.1:' + server.address().port;
  let p = new MN.MultisigProvider(url, 'local', Date.now() + 30000);
  await Promise.all(Array.from({ length: 12 }, () => p.call('chain.get_chain_id', {})));
  assert(peak <= 2 && p.stats.maxActive <= 2 && p.stats.sockets <= 2 && sockets.size <= 2, `peak ${peak} sockets ${p.stats.sockets}`); p.close();
  mode = '503'; hits = 0; p = new MN.MultisigProvider(url, 'local', Date.now() + 30000);
  await assert.rejects(() => p.call('chain.get_head_info', {}), /withheld/); assert.equal(hits, 3); assert.equal(p.stats.retries, 2);
  hits = 0; await assert.rejects(() => p.call('chain.submit_transaction', {}), /withheld/); assert.equal(hits, 1, 'writes are never retried'); p.close();
  mode = 'huge'; p = new MN.MultisigProvider(url, 'local', Date.now() + 30000); await assert.rejects(() => p.call('chain.get_head_info', {})); p.close();
  await assert.rejects(async () => new MN.MultisigProvider(url, 'local', Date.now() + 3000).call('chain.unknown_method', {}), /Unsupported/);
  mode = 'trickle'; p = new MN.MultisigProvider(url, 'local', Date.now() + 2500); let begun = Date.now();
  await assert.rejects(() => p.call('chain.get_head_info', {})); assert(Date.now() - begun < 6000, 'a trickling server cannot extend a request past the wall clock'); p.close();
  mode = 'hang'; p = new MN.MultisigProvider(url, 'local', Date.now() + 1500); const started = Date.now();
  await assert.rejects(() => p.call('chain.get_head_info', {})); assert(Date.now() - started < 9000, 'command deadline bounds every read'); p.close();
  assert.throws(() => new MN.MultisigProvider('http://user:pw@127.0.0.1:1/', 'local', Date.now() + 1000), /credentials/);
  assert.throws(() => new MN.MultisigProvider('https://api.koinos.io/', 'local', Date.now() + 1000), /loopback/);
  assert.throws(() => MN.multisigProvider({ name: 'local', chainId: X.chainId }, url, Date.now() + 1000, 'http://127.0.0.1:2/'), /corroborating/);
});

// ---------------------------------------------------------------------------------------------- bootstrap
async function deployPackage(dir) {
  const inputs = { schema: 1, template: MP.TEMPLATE_NAME, templateVersion: MP.TEMPLATE_VERSION, network: 'local', chainId: X.chainId, koinContract: X.koin, treasury: X.treasury.address, owners: X.owners.map(s => s.address), threshold: 3 };
  const inputsText = JSON.stringify(inputs, null, 2) + '\n'; const abi = '{"methods":{}}';
  const artifact = { schema: 1, template: MP.TEMPLATE_NAME, templateVersion: MP.TEMPLATE_VERSION, inputsSha256: VP.sha(inputsText), sourceSha256: VP.sha('src'), wasmSha256: VP.sha(X.code), wasmSize: X.code.length, abiSha256: VP.sha(abi), toolchain: { treeSha256: VP.sha('tree') } };
  const art = path.join(dir, 'artifact'); fs.mkdirSync(art, { mode: 0o700 });
  fs.writeFileSync(path.join(art, 'inputs.json'), inputsText); fs.writeFileSync(path.join(art, 'artifact.json'), JSON.stringify(artifact)); fs.writeFileSync(path.join(art, 'contract.wasm'), X.code); fs.writeFileSync(path.join(art, 'treasury.abi'), abi);
  return { art, network: { name: 'local', chainId: X.chainId } };
}
test('bootstrap: unused-address checks, exact upload review, treasury-key-only signature', async t => {
  const dir = temp(t); const { art, network } = await deployPackage(dir); const f = X.fixture(dir);
  const fresh = { noCode: true, nonce: undefined, policy: undefined };
  let rpc = await X.rpcFixture(f, fresh); let p = rpc.provider();
  const pkg = await M.prepareDeploy(art, network, p, '500000000'); p.close();
  const review = await M.reviewDeploy(pkg); assert.equal(review.status, 'prepared'); assert.deepEqual(review.flags, { call: true, transaction: true, upload: true });
  await assert.rejects(() => M.signDeploy(pkg, X.owners[0], review.id), /treasury address key/);
  const signed = await M.signDeploy(pkg, X.treasury, review.id); assert.equal((await M.reviewDeploy(signed)).status, 'bootstrap-signed');
  await assert.rejects(() => M.signDeploy(signed, X.treasury, review.id), /unsigned/);
  for (const mutate of [x => x.transaction.operations[0].upload_contract.authorizes_upload_contract = false, x => x.inputs.threshold = 4, x => x.artifact.wasmSha256 = '00'.repeat(32), x => x.transaction.header.nonce = 'KAI=']) {
    const x = structuredClone(signed); mutate(x); await assert.rejects(() => M.reviewDeploy(x));
  }
  await rpc.close();
  for (const [state, pattern] of [[{ nonce: 'KAE=' }, /already paid/], [{ noCode: false }, /already has a contract/], [{ storedPolicy: true }, /storage/], [{ allowances: [{ spender: X.outsider.address, value: '1' }] }, /allowances/]]) {
    rpc = await X.rpcFixture(f, { ...fresh, ...state }); p = rpc.provider();
    await assert.rejects(() => M.prepareDeploy(art, network, p, '500000000'), pattern); p.close(); await rpc.close();
  }
});

test('verify-deployment: manifest only when every on-chain check passes; each bootstrap attack is reported', async t => {
  const dir = temp(t); const { art, network } = await deployPackage(dir); const f = X.fixture(dir);
  let rpc = await X.rpcFixture(f, { noCode: true, nonce: undefined }); let p = rpc.provider();
  const prepared = await M.prepareDeploy(art, network, p, '500000000'); p.close(); await rpc.close();
  const signed = await M.signDeploy(prepared, X.treasury, prepared.transaction.id);
  const good = { tx: signed.transaction, irreversible: true, nonce: 'KAE=', code: X.code, policy: { owners: X.owners.map(s => s.address), threshold: 3, version: '0' } };
  rpc = await X.rpcFixture(f, good); p = rpc.provider(); const ok = await M.verifyDeployment(signed, p); p.close(); await rpc.close();
  assert.equal(ok.status, 'deployment-verified'); assert.equal(M.validateManifest(ok.manifest), 'local'); assert.equal(ok.manifest.policy.version, '0');
  assert.match(ok.checks.fundCheck, /not checked/); assert.equal(ok.manifest.treasury.bootstrap.transactionId, signed.transaction.id);
  for (const [state, failure] of [[{ storedPolicy: true }, /storage/], [{ allowances: [{ spender: X.outsider.address, value: '1' }] }, /allowances/], [{ nonce: 'KAI=' }, /nonce/],
    [{ policy: { owners: X.owners.map(s => s.address), threshold: 3, version: '1' } }, /initial policy/], [{ authority: { upload: false } }, /flags/], [{ code: Buffer.from('other') }, /hash/]]) {
    rpc = await X.rpcFixture(f, { ...good, ...state }); p = rpc.provider(); const r = await M.verifyDeployment(signed, p); p.close(); await rpc.close();
    assert.equal(r.status, 'refused'); assert(r.failures.some(x => failure.test(x)), JSON.stringify(r.failures)); assert.equal(r.manifest, undefined);
  }
  rpc = await X.rpcFixture(f, { ...good, irreversible: false }); p = rpc.provider(); assert.equal((await M.verifyDeployment(signed, p)).status, 'included-not-irreversible'); p.close(); await rpc.close();
  // Checks passed, but at a block that is not irreversible yet (head 110, LIB 100): nothing is written.
  rpc = await X.rpcFixture(f, { ...good, height: 110, lib: '100' }); p = rpc.provider();
  const pending = await M.verifyDeployment(signed, p, 1000); p.close(); await rpc.close();
  assert.equal(pending.status, 'observation-not-irreversible'); assert.equal(pending.manifest, undefined);
  // State changes while the checklist is being read (same head, new state root): refused, no manifest.
  let n = 0; rpc = await X.rpcFixture(f, { ...good, beforeCall: async (method, params, state) => { if (method === 'chain.read_contract' && params.contract_id === X.koin) state.root = 'changed-mid-read-' + n++; } });
  p = rpc.provider(); await assert.rejects(() => M.verifyDeployment(signed, p), /kept moving/); p.close(); await rpc.close();
  rpc = await X.rpcFixture(f, { ...good, included: { ...signed.transaction, operations: [{ upload_contract: { ...signed.transaction.operations[0].upload_contract, authorizes_upload_contract: false } }] } });
  p = rpc.provider(); await assert.rejects(() => M.verifyDeployment(signed, p), /differs/); p.close(); await rpc.close();
});
