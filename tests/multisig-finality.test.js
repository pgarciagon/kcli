// Synthetic Mainnet IDs and disposable signers only; no public endpoint is contacted.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const { utils } = require('koilib');
const M = require('../dist/multisig');
const MN = require('../dist/multisig-network');
const MP = require('../dist/multisig-protocol');
const VP = require('../dist/vortex-protocol');
const { MAINNET_CHAIN } = require('../dist/vortex-network');
const X = require('./multisig-fixture');
const urls = ['https://a.example-rpc.org/', 'https://b.other-rpc.net/'];

function privateJson(file, value) {
  fs.writeFileSync(file, JSON.stringify(value, null, 2), { mode: 0o600 });
}
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'kcli-finality-'));
  fs.chmodSync(dir, 0o700);
  const home = process.env.HOME; process.env.HOME = dir;
  t.after(() => { process.env.HOME = home; fs.rmSync(dir, { recursive: true, force: true }); });
  const manifest = X.manifestFor();
  manifest.network = { name: 'mainnet', chainId: MAINNET_CHAIN, rpcs: urls.map((url, i) => ({ url, operator: 'fixture-operator-' + i })) };
  manifest.token.contract = MN.PUBLIC_KOIN.mainnet;
  const keys = crypto.generateKeyPairSync('ed25519');
  const der = keys.publicKey.export({ type: 'spki', format: 'der' });
  const attest = (text, purpose) => {
    const file = path.join(dir, purpose + '-review.json'), digest = VP.sha(text);
    privateJson(file, { schema: 1, kind: `kcli-multisig-${purpose}-review`, manifestSha256: digest,
      publicKey: utils.encodeBase64url(der), signature: utils.encodeBase64url(crypto.sign(null, Buffer.from(`kcli-multisig-${purpose}-v1\n` + digest), keys.privateKey)) });
    return file;
  };
  const reviewKey = VP.sha(der), reviewFile = attest(JSON.stringify(manifest, null, 2), 'manifest');
  return { ...X.fixture(dir, manifest, reviewFile, reviewKey), dir, reviewKey, reviewFile, attest };
}
async function online(t, f, first = {}, second = {}) {
  const defaults = { height: 110, lib: '90', time: String(Date.now() - 1000), root: utils.encodeBase64url(Buffer.from('1220' + VP.sha('finality-state'), 'hex')) };
  const primary = await X.rpcFixture(f, { ...defaults, ...first });
  const witness = await X.rpcFixture(f, { ...defaults, ...second });
  t.after(primary.close); t.after(witness.close);
  const sync = async () => {
    if (primary.state.tx) {
      witness.state.tx = primary.state.tx;
      const call = primary.state.tx.operations[0].call_contract;
      if (call) {
        const action = await MP.reviewOperation(call, X.treasury.address, f.ctx.koin);
        if (action.kind === 'policy') primary.state.policy = witness.state.policy = { owners: action.owners, threshold: action.threshold, version: '1' };
      }
    }
  };
  for (const rpc of [primary, witness]) {
    const before = rpc.state.beforeCall;
    rpc.state.beforeCall = async (...args) => { await sync(); await before?.(...args); if (rpc.watch) rpc.watch(...args); };
  }
  // Real provider identity/profile checks, with call() replaced at this fixture boundary only.
  const provider = MN.multisigProvider(f.manifest.network, urls[0], Date.now() + 30000, urls[1]);
  provider.call = primary.answer; provider.witness.call = witness.answer;
  t.after(() => provider.close());
  return { primary, witness, provider };
}
async function approved(f, kind = 'transfer') {
  return X.signedBy(f, await f.pkg(kind), X.owners.slice(0, 3));
}
function included(rpc, pkg) {
  rpc.primary.state.tx = pkg.transaction;
  rpc.witness.state.tx = pkg.transaction;
}
function finality(rpc, primary, witness = primary) {
  rpc.primary.state.lib = String(primary); rpc.witness.state.lib = String(witness);
}
function later(t, fn, ms = 750) {
  const timer = setTimeout(fn, ms); t.after(() => clearTimeout(timer));
}
function protect(rpc, pkg, nonce = 2) {
  const bytes = JSON.stringify(pkg), txBytes = JSON.stringify(pkg.transaction);
  const dir = M.journalDirectory(pkg.transaction.header.chain_id, pkg.transaction.header.payer);
  const intent = path.join(dir, pkg.transaction.id.slice(2) + '.json'), lock = path.join(dir, `nonce-${nonce}.json`);
  let checks = 0;
  const check = () => {
    assert.equal(JSON.stringify(pkg), bytes, 'waiting cannot change signed package bytes');
    assert.equal(JSON.stringify(rpc.primary.state.tx), txBytes, 'exact signed transaction sent');
    assert.equal(JSON.stringify(JSON.parse(fs.readFileSync(intent)).package), bytes);
    assert.equal(JSON.parse(fs.readFileSync(lock)).id, pkg.transaction.id);
    assert.equal(fs.statSync(intent).mode & 0o777, 0o600);
    assert.equal(fs.statSync(lock).mode & 0o777, 0o600);
    checks++;
  };
  rpc.primary.watch = method => {
    if (method === 'chain.submit_transaction') {
      assert(fs.existsSync(intent) && fs.existsSync(lock), 'durable protection precedes submission');
    } else if (rpc.primary.state.tx) check();
  };
  return () => {
    check(); assert(checks > 1, 'journal protection checked during readback');
    assert.equal(rpc.primary.state.sends, 1); assert.equal(rpc.witness.state.sends, 0);
  };
}
async function bootstrap(t, f, rpc) {
  const art = path.join(f.dir, 'artifact'); fs.mkdirSync(art, { mode: 0o700 });
  const inputs = { schema: 1, template: MP.TEMPLATE_NAME, templateVersion: MP.TEMPLATE_VERSION, network: 'mainnet', chainId: MAINNET_CHAIN,
    koinContract: f.ctx.koin, treasury: X.treasury.address, owners: X.owners.map(s => s.address), threshold: 3 };
  const inputsText = JSON.stringify(inputs, null, 2) + '\n', abi = '{"methods":{}}';
  fs.writeFileSync(path.join(art, 'inputs.json'), inputsText, { mode: 0o600 });
  privateJson(path.join(art, 'artifact.json'), { schema: 1, template: MP.TEMPLATE_NAME, templateVersion: MP.TEMPLATE_VERSION,
    inputsSha256: VP.sha(inputsText), sourceSha256: VP.sha('synthetic-source'), wasmSha256: VP.sha(X.code), wasmSize: X.code.length,
    abiSha256: VP.sha(abi), toolchain: { treeSha256: VP.sha('synthetic-toolchain') } });
  fs.writeFileSync(path.join(art, 'contract.wasm'), X.code, { mode: 0o600 });
  fs.writeFileSync(path.join(art, 'treasury.abi'), abi, { mode: 0o600 });
  const pkg = await M.prepareDeploy(art, f.manifest.network, rpc.provider, '500000000');
  return M.signDeploy(pkg, X.treasury, pkg.transaction.id);
}
function deployed(rpc) {
  for (const r of [rpc.primary, rpc.witness]) { r.state.noCode = false; r.state.nonce = 'KAE='; }
}
const fresh = { noCode: true, nonce: undefined };

test('Mainnet inclusion rejects mismatched enclosing block and receipt anchors on either RPC', async t => {
  const f = fixture(t), rpc = await online(t, f), pkg = await approved(f);
  included(rpc, pkg); finality(rpc, 100);
  for (const side of [rpc.primary, rpc.witness]) {
    for (const anchor of [{ blockId: '0x1220' + '99'.repeat(32) }, { headerHeight: '999' }, { receiptId: '0x1220' + '99'.repeat(32) }, { receiptHeight: '999' }]) {
      side.state.anchor = anchor;
      await assert.rejects(() => M.reconcile(f.ctx, rpc.provider, pkg), /Inclusion block or receipt anchor/);
      delete side.state.anchor;
    }
  }
  assert.equal((await M.reconcile(f.ctx, rpc.provider, pkg)).status, 'irreversible-and-verified');
});
for (const kind of ['transfer', 'policy', 'bootstrap']) {
  test(`Mainnet ${kind}: bounded witness head lag waits without premature completion or resend`, async t => {
    const f = fixture(t), boot = kind === 'bootstrap', rpc = await online(t, f, boot ? fresh : {}, boot ? fresh : {});
    const pkg = boot ? await bootstrap(t, f, rpc) : await approved(f, kind), check = protect(rpc, pkg, boot ? 1 : 2);
    rpc.witness.state.height = 99;
    later(t, () => { rpc.witness.state.height = 110; finality(rpc, 100); }, 1500);
    const started = Date.now();
    const result = boot ? await M.submitDeploy(pkg, rpc.provider, pkg.transaction.id, 5000, false) : await M.submit(f.ctx, rpc.provider, pkg, pkg.transaction.id, 5000);
    assert.equal(result.status, boot ? 'irreversible' : 'irreversible-and-verified');
    assert(Date.now() - started >= 1500); check();
  });
}
test('Mainnet witness head lag times out unknown with one-shot journal protection; a fork still fails closed', async t => {
  const f = fixture(t), rpc = await online(t, f, {}, { height: 99 }), pkg = await approved(f), check = protect(rpc, pkg);
  const started = Date.now(), result = await M.submit(f.ctx, rpc.provider, pkg, pkg.transaction.id, 1000);
  assert.equal(result.status, 'submitted-unconfirmed'); assert(Date.now() - started >= 1000); check();
  await assert.rejects(() => M.submit(f.ctx, rpc.provider, pkg, pkg.transaction.id, 1000), /submission intent/);
  rpc.witness.state.fork = true;
  await assert.rejects(() => M.reconcile(f.ctx, rpc.provider, pkg), /canonical chain/);
  rpc.witness.state.fork = false; rpc.witness.state.height = 110; finality(rpc, 100);
  assert.equal((await M.reconcile(f.ctx, rpc.provider, pkg)).status, 'irreversible-and-verified'); check();
});
test('first-use journal ancestor entries are fsynced before any submission, including retry after a sync failure', async t => {
  const f = fixture(t), rpc = await online(t, f), pkg = await approved(f);
  const sync = fs.fsyncSync, open = fs.openSync, close = fs.closeSync, fds = new Map(), synced = [];
  const root = path.join(f.dir, '.kcli');
  let fail = true;
  fs.openSync = (...args) => { const fd = open(...args); fds.set(fd, args[0]); return fd; };
  fs.closeSync = fd => { fds.delete(fd); return close(fd); };
  fs.fsyncSync = fd => {
    const p = fds.get(fd); if (p && fs.statSync(p).isDirectory()) {
      if (fail && p === f.dir) { fail = false; throw Error('synthetic directory fsync failure'); }
      synced.push(p);
    }
    return sync(fd);
  };
  t.after(() => { fs.fsyncSync = sync; fs.openSync = open; fs.closeSync = close; });
  await assert.rejects(() => M.submit(f.ctx, rpc.provider, pkg, pkg.transaction.id, 0), /synthetic directory fsync failure/);
  assert.equal(rpc.primary.state.sends, 0);
  rpc.primary.watch = method => {
    if (method === 'chain.submit_transaction') {
      let dir = path.join(f.dir, '.kcli', 'multisig-journal', VP.sha(pkg.transaction.header.chain_id).slice(0, 16), pkg.transaction.header.payer);
      for (;;) {
        assert(synced.includes(dir), `directory not durable before send: ${dir}`);
        if (dir === f.dir) break;
        dir = path.dirname(dir);
      }
    }
  };
  assert.equal((await M.submit(f.ctx, rpc.provider, pkg, pkg.transaction.id, 0)).status, 'included');
  assert.equal(rpc.primary.state.sends, 1); assert(fs.existsSync(root));
});

for (const kind of ['transfer', 'policy']) {
  test(`Mainnet ${kind}: reversible canonical inclusion and either lagging LIB stay pending`, async t => {
    const f = fixture(t), rpc = await online(t, f), pkg = await approved(f, kind); included(rpc, pkg);
    for (const [a, b] of [[90, 90], [100, 90], [90, 100]]) {
      finality(rpc, a, b);
      const result = await M.reconcile(f.ctx, rpc.provider, pkg);
      assert.equal(result.status, 'included'); assert.equal(result.height, '100'); assert.equal(result.manifest, undefined);
    }
    finality(rpc, 100);
    const result = await M.reconcile(f.ctx, rpc.provider, pkg);
    assert.equal(result.status, 'irreversible-and-verified');
    if (kind === 'policy') assert.equal(result.manifest.policy.version, '1');
    assert.equal(rpc.primary.state.sends, 0); assert.equal(rpc.witness.state.sends, 0);
  });
  test(`Mainnet ${kind}: --wait survives reversible inclusion, submits exact bytes once`, async t => {
    const f = fixture(t), rpc = await online(t, f), pkg = await approved(f, kind), check = protect(rpc, pkg);
    later(t, () => finality(rpc, 100));
    const started = Date.now(), result = await M.submit(f.ctx, rpc.provider, pkg, pkg.transaction.id, 5000);
    const elapsed = Date.now() - started;
    assert.equal(result.status, 'irreversible-and-verified'); assert(elapsed >= 750 && elapsed < 4500, `elapsed ${elapsed} ms`);
    check();
    t.diagnostic(`wait=5000ms elapsed=${elapsed}ms status=${result.status} sends=${rpc.primary.state.sends}`);
  });
  test(`Mainnet ${kind}: deadline leaves inclusion nonfinal and intent/nonce protection intact`, async t => {
    const f = fixture(t), rpc = await online(t, f), pkg = await approved(f, kind), check = protect(rpc, pkg);
    const started = Date.now(), result = await M.submit(f.ctx, rpc.provider, pkg, pkg.transaction.id, 1000);
    assert.equal(result.status, 'included'); assert(Date.now() - started >= 1000); check();
    // Model a reorganized-away pending policy: preflight can pass again, but the journal still forbids resending.
    if (kind === 'policy') {
      rpc.primary.state.tx = rpc.witness.state.tx = null;
      rpc.primary.state.policy = rpc.witness.state.policy = structuredClone(f.manifest.policy);
    }
    await assert.rejects(() => M.submit(f.ctx, rpc.provider, pkg, pkg.transaction.id, 1000), /submission intent/);
    const other = await approved(f, kind === 'transfer' ? 'policy' : 'transfer');
    await assert.rejects(() => M.submit(f.ctx, rpc.provider, other, other.transaction.id, 1000), /treasury nonce/);
    if (kind === 'policy') included(rpc, pkg);
    check(); finality(rpc, 100);
    assert.equal((await M.reconcile(f.ctx, rpc.provider, pkg)).status, 'irreversible-and-verified'); check();
  });
}
test('Mainnet reversible reversion is not final until both LIBs advance', async t => {
  const f = fixture(t), rpc = await online(t, f, { reverted: true }, { reverted: true }), pkg = await approved(f);
  included(rpc, pkg); finality(rpc, 100, 90);
  assert.equal((await M.reconcile(f.ctx, rpc.provider, pkg)).status, 'included-reverted');
  rpc.primary.state.tx = rpc.witness.state.tx = null;
  const check = protect(rpc, pkg); later(t, () => finality(rpc, 100));
  const result = await M.submit(f.ctx, rpc.provider, pkg, pkg.transaction.id, 5000);
  assert.equal(result.status, 'reverted'); check();
});
test('Mainnet inclusion still fails closed on forks, receipt/event conflicts, body and signature tampering', async t => {
  const f = fixture(t), rpc = await online(t, f), pkg = await approved(f); included(rpc, pkg);
  for (const [mutation, pattern] of [
    [{ fork: true }, /canonical chain/], [{ reverted: true }, /receipt or events/], [{ eventTo: X.outsider.address }, /receipt or events/],
    [{ included: { ...pkg.transaction, header: { ...pkg.transaction.header, rc_limit: '1' } } }, /differs/],
    [{ included: { ...pkg.transaction, signatures: pkg.transaction.signatures.slice(0, 2) } }, /quorum/],
    [{ included: { ...pkg.transaction, signatures: [utils.encodeBase64url(Buffer.alloc(65))] } }, /signature/i],
  ]) {
    Object.assign(rpc.witness.state, mutation);
    await assert.rejects(() => M.reconcile(f.ctx, rpc.provider, pkg), pattern);
    for (const key of Object.keys(mutation)) delete rpc.witness.state[key];
  }
  rpc.primary.state.fork = true;
  assert.equal((await M.reconcile(f.ctx, rpc.provider, pkg)).status, 'unknown');
  assert.equal(rpc.primary.state.sends, 0);
});
test('Mainnet final canonical rechecks and genuine read failures are not treated as pending finality', async t => {
  const f = fixture(t), rpc = await online(t, f), pkg = await approved(f); included(rpc, pkg); finality(rpc, 100);
  let heads = 0;
  rpc.primary.watch = method => { if (method === 'chain.get_head_info' && ++heads === 2) rpc.primary.state.fork = true; };
  await assert.rejects(() => M.reconcile(f.ctx, rpc.provider, pkg), /Canonical finality changed/);
  rpc.primary.watch = undefined; rpc.primary.state.fork = false; rpc.witness.state.failure = 'chain.get_head_info';
  await assert.rejects(() => M.reconcile(f.ctx, rpc.provider, pkg), /synthetic sensitive/);
  delete rpc.witness.state.failure; rpc.primary.state.tx = rpc.witness.state.tx = null; finality(rpc, 90);
  rpc.primary.watch = method => { if (method === 'transaction_store.get_transactions_by_id') rpc.witness.state.failure = 'chain.get_head_info'; };
  const started = Date.now(), result = await M.submit(f.ctx, rpc.provider, pkg, pkg.transaction.id, 5000);
  assert.equal(result.status, 'submitted-unconfirmed'); assert(Date.now() - started < 1500);
  assert.equal(rpc.primary.state.sends, 1);
});
test('Mainnet submit-deploy waits for both LIBs without resending or changing bootstrap bytes', async t => {
  const f = fixture(t), rpc = await online(t, f, fresh, fresh), pkg = await bootstrap(t, f, rpc), check = protect(rpc, pkg, 1);
  later(t, () => finality(rpc, 100, 90), 250); later(t, () => finality(rpc, 100), 1500);
  const started = Date.now(), result = await M.submitDeploy(pkg, rpc.provider, pkg.transaction.id, 5000, false);
  assert.equal(result.status, 'irreversible'); assert(Date.now() - started >= 1500); assert.equal(result.manifest, undefined); check();
});
test('Mainnet submit-deploy timeout retains reversible reversion and persistent one-shot protection', async t => {
  const f = fixture(t), rpc = await online(t, f, { ...fresh, reverted: true }, { ...fresh, reverted: true });
  const pkg = await bootstrap(t, f, rpc), check = protect(rpc, pkg, 1);
  const result = await M.submitDeploy(pkg, rpc.provider, pkg.transaction.id, 1000, false);
  assert.equal(result.status, 'included-reverted'); assert.equal(result.manifest, undefined); check();
  await assert.rejects(() => M.submitDeploy(pkg, rpc.provider, pkg.transaction.id, 1000, false), /submission intent/); check();
  deployed(rpc); finality(rpc, 100);
  assert.equal((await M.verifyDeployment(pkg, rpc.provider)).status, 'reverted'); check();
});
test('Mainnet verify-deployment gates manifests on bootstrap AND both observation anchors', async t => {
  const f = fixture(t), rpc = await online(t, f, fresh, fresh), pkg = await bootstrap(t, f, rpc); included(rpc, pkg); deployed(rpc);
  for (const [a, b, status] of [[90, 90, 'included-not-irreversible'], [100, 90, 'included-not-irreversible'], [100, 100, 'observation-not-irreversible'], [110, 100, 'observation-not-irreversible']]) {
    finality(rpc, a, b); const result = await M.verifyDeployment(pkg, rpc.provider);
    assert.equal(result.status, status); assert.equal(result.manifest, undefined);
  }
  later(t, () => finality(rpc, 110));
  const result = await M.verifyDeployment(pkg, rpc.provider, 5000);
  assert.equal(result.status, 'deployment-verified'); assert.equal(M.validateManifest(result.manifest), 'mainnet');
  assert.equal(rpc.primary.state.sends, 0); assert.equal(rpc.witness.state.sends, 0);
});

function cli(t, f, rpc, args) {
  return new Promise((resolve, reject) => {
    const child = spawn('kcli', args, { env: { ...process.env, HOME: f.dir,
      NODE_OPTIONS: '--require ' + path.join(__dirname, 'fixtures/multisig-rpc-preload.cjs'),
      KCLI_TEST_RPC_ROUTES: JSON.stringify({ [urls[0]]: rpc.primary.url, [urls[1]]: rpc.witness.url }) }, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    const timer = setTimeout(() => { child.kill(); reject(Error('Fixture CLI deadline')); }, 15000);
    child.stdout.on('data', d => stdout += d); child.stderr.on('data', d => stderr += d);
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('close', code => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
  });
}
const onlineArgs = ['--network', 'mainnet', '--rpc', urls[0], '--corroborating-rpc', urls[1], '--timeout', '10'];
function manifestArgs(f) { return ['--manifest', f.manifestFile, '--review', f.reviewFile, '--review-key', f.reviewKey]; }
for (const [kind, mode, status, code] of [
  ['transfer', 'advance', 'irreversible-and-verified', 0], ['transfer', 'timeout', 'included', 3], ['transfer', 'revert', 'reverted', 1],
  ['policy', 'advance', 'irreversible-and-verified', 0], ['policy', 'timeout', 'included', 3],
]) {
  test(`isolated PATH/HOME CLI: Mainnet ${kind} submit ${mode} has status ${status} and exit ${code}`, async t => {
    const f = fixture(t), rpc = await online(t, f, { reverted: mode === 'revert' }, { reverted: mode === 'revert' });
    const pkg = await approved(f, kind), check = protect(rpc, pkg), file = path.join(f.dir, 'approved.json'); privateJson(file, pkg);
    if (mode !== 'timeout') later(t, () => finality(rpc, 100), 1200);
    const result = await cli(t, f, rpc, ['multisig', 'submit', file, ...manifestArgs(f), ...onlineArgs, '--id', pkg.transaction.id, '--wait', mode === 'timeout' ? '1' : '5']);
    assert.equal(result.code, code, result.stderr); assert.equal(JSON.parse(result.stdout).status, status); check();
    const out = path.join(f.dir, 'next-policy.json');
    const policyArgs = kind === 'policy' ? ['--manifest-out', out] : [];
    const reconciled = await cli(t, f, rpc, ['multisig', 'reconcile', file, ...manifestArgs(f), ...onlineArgs, ...policyArgs]);
    assert.equal(reconciled.code, code, reconciled.stderr); assert.equal(JSON.parse(reconciled.stdout).status, status); check();
    if (kind === 'policy') {
      assert.equal(fs.existsSync(out), code === 0, 'only a verified policy result can write the next manifest');
      if (code === 0) assert.equal(JSON.parse(fs.readFileSync(out)).policy.version, '1');
    }
    assert.equal(JSON.stringify(JSON.parse(fs.readFileSync(file))), JSON.stringify(pkg));
  });
}
test('isolated CLI: bootstrap waiting and verify-deployment exit 3 never writes a premature manifest', async t => {
  const f = fixture(t), rpc = await online(t, f, fresh, fresh), pkg = await bootstrap(t, f, rpc);
  const file = path.join(f.dir, 'bootstrap.json'), out = path.join(f.dir, 'verified.json'); privateJson(file, pkg);
  const review = f.attest(M.bootstrapDigestText(pkg), 'bootstrap'), reviewArgs = ['--review', review, '--review-key', f.reviewKey];
  const check = protect(rpc, pkg, 1); later(t, () => finality(rpc, 100), 1200);
  const submitted = await cli(t, f, rpc, ['multisig', 'submit-deploy', file, ...onlineArgs, ...reviewArgs, '--id', pkg.transaction.id, '--wait', '5']);
  assert.equal(submitted.code, 0, submitted.stderr); assert.equal(JSON.parse(submitted.stdout).status, 'irreversible'); check(); deployed(rpc);
  for (const [a, b, status] of [[90, 90, 'included-not-irreversible'], [100, 90, 'included-not-irreversible'], [100, 100, 'observation-not-irreversible'], [110, 100, 'observation-not-irreversible']]) {
    finality(rpc, a, b);
    const result = await cli(t, f, rpc, ['multisig', 'verify-deployment', file, ...onlineArgs, ...reviewArgs, '--manifest-out', out, '--wait', '1']);
    assert.equal(result.code, 3, result.stderr); assert.equal(JSON.parse(result.stdout).status, status); assert(!fs.existsSync(out)); check();
  }
  finality(rpc, 110);
  const result = await cli(t, f, rpc, ['multisig', 'verify-deployment', file, ...onlineArgs, ...reviewArgs, '--manifest-out', out, '--wait', '1']);
  assert.equal(result.code, 0, result.stderr); assert.equal(JSON.parse(result.stdout).status, 'deployment-verified');
  assert.equal(M.validateManifest(JSON.parse(fs.readFileSync(out))), 'mainnet'); check();
});
