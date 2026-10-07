// Explicit opt-in harness: synthetic wallets + a NEW isolated Koinos chain only.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const http = require('node:http');
const assert = require('node:assert/strict');
const { spawn, spawnSync } = require('node:child_process');
const { Contract, Transaction, utils } = require('koilib');
const W = require('../dist/named-wallets');
const V = require('../dist/vortex');
const P = require('../dist/vortex-protocol');
const F = require('../dist/secure-files');
const root = path.resolve(__dirname, '..');
const password = 'synthetic-disposable-exercise-password';
const source = process.argv[2];
assert(source, 'give the exact clean pinned upstream checkout');
const dir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'kcli-vortex-exercise-')); fs.chmodSync(dir, 0o700);
const home = path.join(dir, 'home'); fs.mkdirSync(home, { mode: 0o700 });
const wallets = path.join(home, 'wallets'); const journal = path.join(dir, 'journal'); fs.mkdirSync(journal, { mode: 0o700 });
const runId = 'kcli-vortex-' + new Date().toISOString().slice(0, 10).replace(/-/g, '') + '-' + crypto.randomBytes(5).toString('hex');
const results = []; let rpc, deployment, manifestFile, abiFile, ctx, relayServer; let sequence = 0; const cli = process.env.KCLI_TEST_EXECUTABLE || 'kcli';
async function command(executable, argv, input, env = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, argv, { cwd: root, env: { ...process.env, ...env, HOME: home }, stdio: ['pipe', 'pipe', 'pipe'] });
    const output = [], errors = []; child.stdout.on('data', b => output.push(b)); child.stderr.on('data', b => errors.push(b));
    const timeout = setTimeout(() => { child.kill('SIGKILL'); reject(Error('Local exercise command timed out')); }, 180000);
    child.on('error', reject); child.on('close', status => { clearTimeout(timeout); resolve({ status, stdout: Buffer.concat(output).toString(), stderr: Buffer.concat(errors).toString() }); }); child.stdin.end(input);
  });
}
async function terminal(argv, inputs) {
  const result = await command('python3', [path.join(__dirname, 'vortex-pty.py')], JSON.stringify({ argv: [cli, ...argv], inputs, home }));
  assert.equal(result.status, 0, 'terminal driver failed'); const reply = JSON.parse(result.stdout); assert.equal(reply.leaked, false, 'synthetic secret escaped terminal output');
  return reply;
}
const docker = (...args) => command('docker', ['--context', 'colima-vortex-v2-audit', ...args], undefined, { DOCKER_CONFIG: path.join(os.homedir(), '.docker') });
async function startRelay() {
  relayServer = http.createServer(async (req, res) => {
    try {
      const chunks = []; let size = 0;
      for await (const b of req) { size += b.length; assert(size <= 1048576); chunks.push(b); }
      const r = await command('docker', ['--context', 'colima-vortex-v2-audit', 'exec', '-i', runId + '-controller', 'node', '/exercise/controller.cjs', 'relay'], Buffer.concat(chunks), { DOCKER_CONFIG: path.join(os.homedir(), '.docker') });
      const request = JSON.parse(Buffer.concat(chunks));
      let response; try { response = JSON.parse(r.stdout); } catch {}
      if (r.status !== 0 || response?.error || !response?.result) {
        const diagnostic = JSON.stringify({ method: request.method, status: r.status, error: response?.error || null, stderr: r.stderr.slice(0, 1200), prefix: response ? undefined : r.stdout.slice(0, 300) }).replace(/\b[5KL][1-9A-HJ-NP-Za-km-z]{49,51}\b/g, '[redacted-key]');
        fs.appendFileSync(path.join(dir, 'relay-diagnostic.jsonl'), diagnostic + '\n', { mode: 0o600 });
      }
      assert.equal(r.status, 0); res.setHeader('content-type', 'application/json'); res.end(r.stdout);
    } catch { res.writeHead(503); res.end('Local relay unavailable'); }
  });
  await new Promise(resolve => relayServer.listen(0, '127.0.0.1', resolve));
  return 'http://127.0.0.1:' + relayServer.address().port;
}
async function control(action, ...args) {
  if (action === 'execute') assert.equal((await docker('cp', path.join(dir, 'raw-transaction.json'), runId + '-controller:/exercise/raw-transaction.json')).status, 0);
  const r = await docker('exec', runId + '-controller', 'node', '/exercise/controller.cjs', action, ...args.map(String));
  assert.equal(r.status, 0, 'local controller failed: ' + r.stderr); return r.stdout;
}
const binding = () => ['--manifest', manifestFile, '--abi', abiFile];
const online = () => ['--network', 'local', '--rpc', rpc, '--contract', deployment.bridge, ...binding()];
async function check(name, fn) {
  const data = await fn(); results.push({ name, passed: true, ...(data || {}) });
  console.log('PASS ' + name); writeEvidence();
}
function writeEvidence(error) {
  const record = { schema: 1, runId, cliVersion: require('../package.json').version, networkProfile: 'local', mainnetProfileExecuted: false, upstream: P.VORTEX_PIN, syntheticOnly: true, publicChainUsed: false, independentCustody: false, minimumDelayMs: '172800000', build: deployment && { codeSha256: deployment.codeSha256, abiSha256: deployment.abiSha256, sourceSha256: deployment.sourceSha256, variant: 'fresh-initializer', adapterSha256: '9f999b2b4561af7062247a6bf47a47790f0c5d9cabdf548788651955136dcd72' }, results, error: error ? 'Local-chain exercise incomplete; see diagnostics and retained synthetic namespace.' : null };
  fs.writeFileSync(path.join(dir, 'evidence.json'), JSON.stringify(record, null, 2), { mode: 0o600 });
}
async function prepare(action, args = {}, propose = false, expectedFailure = false) {
  const prefix = path.join(dir, String(++sequence).padStart(3, '0') + '-' + action + (propose ? '-proposal' : ''));
  const argumentsFile = prefix + '-args.json'; F.writeExclusive(argumentsFile, args);
  const file = prefix + '-unsigned.json'; const r = await command(cli, ['vortex', 'prepare', action, ...online(), '--args', argumentsFile, '--rc-limit', '300000000', ...(propose ? ['--propose'] : []), '--out', file]);
  if (expectedFailure) { assert.equal(r.status, 1); assert(!fs.existsSync(file)); return r; }
  if (r.status !== 0) {
    try { await V.prepareVortex(ctx, new V.VortexProvider(rpc), await V.encodeAction(ctx, action, args, propose), '300000000'); }
    catch (error) { fs.writeFileSync(path.join(dir, 'prepare-diagnostic.txt'), String(error.stack).replace(/\b[5KL][1-9A-HJ-NP-Za-km-z]{49,51}\b/g, '[redacted-key]'), { mode: 0o600 }); }
  }
  assert.equal(r.status, 0, r.stderr); const pkg = V.readPackage(file); assert.equal(pkg.transaction.signatures.length, 0); return { file, pkg, prefix };
}
async function signPackage(prepared, name, inputFile = prepared.file, role = 'admin', suffix = name) {
  const pkg = V.readPackage(inputFile); const store = new W.NamedWallets(wallets); const who = store.metadata(name).address; const file = prepared.prefix + '-' + suffix + '.json';
  const r = await terminal(['vortex', role === 'admin' ? 'sign' : 'payer-sign', inputFile, ...binding(), '--wallet', name, '--vault-dir', wallets, '--signer', who, '--id', pkg.transaction.id, '--out', file], [{ prompt: 'Wallet password: ', value: password }]);
  assert.equal(r.status, 0, r.stdout); const signed = V.readPackage(file);
  assert.equal(F.canonical({ ...signed.transaction, signatures: [] }), F.canonical({ ...pkg.transaction, signatures: [] }));
  assert(pkg.transaction.signatures.every((s, i) => signed.transaction.signatures[i] === s)); return file;
}
async function signatures(prepared, count, independent = false) {
  let file = prepared.file;
  if (independent) {
    const a = await signPackage(prepared, 'admin-a'), b = await signPackage(prepared, 'admin-b'); file = prepared.prefix + '-merged.json';
    const r = await command(cli, ['vortex', 'merge', a, b, ...binding(), '--out', file]); assert.equal(r.status, 0, r.stderr);
  } else for (const name of ['admin-a', 'admin-b'].slice(0, count)) file = await signPackage(prepared, name, file);
  if (count === 3) file = await signPackage(prepared, 'admin-c', file);
  return signPackage(prepared, 'fee-payer', file, 'payer');
}
async function submit(file) {
  const pkg = V.readPackage(file); const r = await command(cli, ['vortex', 'submit', file, ...online(), '--id', pkg.transaction.id, '--journal-dir', journal, '--wait', '120']);
  if (r.status !== 0) {
    fs.writeFileSync(path.join(dir, 'submit-diagnostic.txt'), r.stdout + '\n' + r.stderr, { mode: 0o600 });
    try { await V.reconcileVortex(ctx, new V.VortexProvider(rpc), pkg); }
    catch (error) { fs.writeFileSync(path.join(dir, 'reconcile-diagnostic.txt'), String(error.stack).replace(/\b[5KL][1-9A-HJ-NP-Za-km-z]{49,51}\b/g, '[redacted-key]'), { mode: 0o600 }); }
    throw Error('CLI submission/finality failed; diagnostic retained in synthetic exercise');
  }
  assert.match(r.stdout, /"status": "irreversible-and-state-verified"/);
  const reconciled = await command(cli, ['vortex', 'reconcile', file, ...online()]);
  assert.equal(reconciled.status, 0, reconciled.stderr); const receipt = F.strictJson(reconciled.stdout);
  assert.equal(receipt.status, 'irreversible-and-state-verified');
  return { transactionId: pkg.transaction.id, blockId: receipt.block, height: receipt.height, resultingStateSha256: P.sha(F.canonical(receipt.result)), stateVerified: true, irreversible: true };
}
async function raw(action, args = {}, count = 2, proposal = false) {
  const c = new Contract({ id: deployment.bridge, abi: normalizedAbi(fs.readFileSync(abiFile, 'utf8')), provider: new V.VortexProvider(rpc) });
  let operation = (await c.functions[action](args, { onlyOperation: true })).operation;
  if (proposal) operation = (await c.functions.propose({ entry_point: operation.call_contract.entry_point, args: operation.call_contract.args ? '0x' + Buffer.from(utils.decodeBase64url(operation.call_contract.args)).toString('hex') : '' }, { onlyOperation: true })).operation;
  const store = new W.NamedWallets(wallets); const payer = store.unlock('fee-payer', password); payer.provider = c.provider;
  const tx = await Transaction.prepareTransaction({ header: { payer: payer.address, rc_limit: '300000000' }, operations: [operation], signatures: [] }, c.provider);
  for (const name of ['admin-a', 'admin-b', 'admin-c'].slice(0, count)) await store.unlock(name, password).signTransaction(tx);
  await payer.signTransaction(tx); fs.writeFileSync(path.join(dir, 'raw-transaction.json'), JSON.stringify(tx), { mode: 0o600 }); return tx;
}
function normalizedAbi(text) {
  const a = JSON.parse(text); a.koilib_types = a.types;
  for (const m of Object.values(a.methods)) { m.entry_point = Number(m['entry-point']); m.read_only = m['read-only']; } return a;
}
async function pauseProducer() { const r = await docker('stop', runId + '-producer'); assert.equal(r.status, 0); }
async function startProducer() {
  const existing = await docker('inspect', runId + '-producer');
  const r = existing.status === 0 ? await docker('start', runId + '-producer') : await docker('run', '-d', '--label', 'kcli.vortex.exercise=' + runId, '--name', runId + '-producer', '--network', runId + '-net', '--mount', 'type=volume,source=vortex-fresh-work-20261003,target=/work,readonly', '--mount', 'type=volume,source=' + runId + '-exercise,target=/exercise,readonly', 'node@sha256:0e910f435308c36ea60b4cfd7b80208044d77a074d16b768a81901ce938a62dc', 'node', '/exercise/controller.cjs', 'producer');
  assert.equal(r.status, 0);
}
(async () => {
  console.log('Synthetic exercise directory: ' + dir);
  await check('installed named wallets created with hidden input and no secret output', async () => {
    for (const name of ['admin-a', 'admin-b', 'admin-c', 'fee-payer']) {
      const r = await terminal(['wallets', 'create', name, '--vault-dir', wallets], [{ prompt: 'New wallet password: ', value: password }, { prompt: 'Confirm wallet password: ', value: password }]); assert.equal(r.status, 0, r.stdout);
    }
    const metadata = new W.NamedWallets(wallets).list(); assert.equal(metadata.length, 4); assert.equal(fs.existsSync(path.join(home, '.kcli')), false);
    F.writeExclusive(path.join(dir, 'input.json'), { admins: ['admin-a', 'admin-b', 'admin-c'].map(name => new W.NamedWallets(wallets).metadata(name).address), payer: new W.NamedWallets(wallets).metadata('fee-payer').address });
  });
  const setup = await command('bash', [path.join(__dirname, 'vortex-local-setup.sh'), source, dir, runId], undefined, { DOCKER_CONFIG: path.join(os.homedir(), '.docker') });
  fs.writeFileSync(path.join(dir, 'setup-diagnostic.txt'), setup.stdout + '\n' + setup.stderr, { mode: 0o600 }); assert.equal(setup.status, 0, 'Fresh-chain bootstrap failed');
  rpc = await startRelay(); deployment = JSON.parse(fs.readFileSync(path.join(dir, 'deployment.json')));
  const input = JSON.parse(fs.readFileSync(path.join(dir, 'input.json'))); abiFile = path.join(dir, 'bridge.abi'); manifestFile = path.join(dir, 'manifest.json');
  const manifest = { schema: 1, source: { repository: P.VORTEX_REPOSITORY, commit: P.VORTEX_PIN, variant: 'fresh-initializer', adapterSha256: '9f999b2b4561af7062247a6bf47a47790f0c5d9cabdf548788651955136dcd72' }, network: { name: 'local', chainId: deployment.chainId }, contract: { address: deployment.bridge, codeSha256: deployment.codeSha256, abiSha256: deployment.abiSha256 }, policy: { reviewed: true, admins: input.admins, adminThreshold: 2, recoveryThreshold: 3, validators: deployment.validators, payer: input.payer, delayMs: '172800000', actionWindowMs: '86400000' } };
  F.writeExclusive(manifestFile, manifest); ctx = V.loadVortex(manifestFile, abiFile);
  await check('actual V2 fresh initialization and immutable binding validated', async () => { await V.chainBinding(ctx, new V.VortexProvider(rpc)); });
  await raw('freeze_setup'); assert.match(await control('execute'), /ACCEPTED/); await control('mine', 62, 172800000);
  await raw('finalize_migration'); assert.match(await control('execute'), /ACCEPTED/);
  await check('fresh-chain setup obeyed full 48-hour delay without shortening contract constant', async () => {});
  const unpauseProposal = await prepare('unpause', {}, true);
  await check('actual contract rejects one admin plus fee payer', async () => { await raw('unpause', {}, 1, true); assert.match(await control('execute'), /REFUSED admin threshold not met/); });
  await check('installed independent signing and merging succeeds with RPC unavailable', async () => {
    assert.equal((await docker('stop', runId + '-jsonrpc')).status, 0);
    unpauseProposal.signed = await signatures(unpauseProposal, 2, true);
    assert.equal((await docker('start', runId + '-jsonrpc')).status, 0);
  });
  await startProducer(); await check('installed CLI proposes unpause and verifies irreversible resulting state', () => submit(unpauseProposal.signed)); await pauseProducer();
  await check('CLI and actual contract both reject execution before delay', async () => {
    await prepare('unpause', {}, false, true); await raw('unpause'); assert.match(await control('execute'), /REFUSED time lock not expired/);
  });
  await control('mine', 62, 172800000); const unpause = await prepare('unpause'); unpause.signed = await signatures(unpause, 2);
  await startProducer(); await check('installed sequential signing executes delayed unpause and verifies finality', () => submit(unpause.signed)); await pauseProducer();
  const pause = await prepare('pause'); pause.signed = await signatures(pause, 2, true); await startProducer(); await check('immediate administrator pause verified irreversibly', () => submit(pause.signed)); await pauseProducer();
  const recoveryArgs = { validators: deployment.recoveryValidators }; const recoveryProposal = await prepare('recover_validators', recoveryArgs, true);
  await check('recovery CLI and actual contract require 3-of-3 rather than admin quorum', async () => {
    const a = await signPackage(recoveryProposal, 'admin-a'); const ab = await signPackage(recoveryProposal, 'admin-b', a);
    const r = await command(cli, ['vortex', 'payer-sign', ab, ...binding(), '--wallet', 'fee-payer', '--vault-dir', wallets, '--signer', input.payer, '--id', recoveryProposal.pkg.transaction.id, '--dry-run']); assert.equal(r.status, 1);
    await raw('recover_validators', recoveryArgs, 2, true); assert.match(await control('execute'), /REFUSED recovery threshold not met/);
    const abc = await signPackage(recoveryProposal, 'admin-c', ab); recoveryProposal.signed = await signPackage(recoveryProposal, 'fee-payer', abc, 'payer');
  });
  await startProducer(); await check('installed 3-of-3 recovery proposal verified irreversibly', () => submit(recoveryProposal.signed)); await pauseProducer();
  await check('actual recovery execution rejects early 3-of-3 transaction', async () => { await raw('recover_validators', recoveryArgs, 3); assert.match(await control('execute'), /REFUSED time lock not expired/); });
  await control('mine', 62, 172800000); const recovery = await prepare('recover_validators', recoveryArgs); recovery.signed = await signatures(recovery, 3);
  await check('actual recovery execution rejects 2 admins even after delay', async () => { await raw('recover_validators', recoveryArgs, 2); assert.match(await control('execute'), /REFUSED recovery threshold not met/); });
  await startProducer(); await check('installed recovery replaces exact validators and verifies irreversible state', () => submit(recovery.signed)); await pauseProducer();
  await check('contract rejects replay of previously included transaction', async () => { fs.writeFileSync(path.join(dir, 'raw-transaction.json'), JSON.stringify(V.readPackage(recovery.signed).transaction), { mode: 0o600 }); assert.match(await control('execute'), /REFUSED.*nonce/); });
  // A membership change requires a separately reviewed successor policy file, not wallet configuration changes.
  manifest.policy.validators = deployment.recoveryValidators; manifestFile = path.join(dir, 'manifest-after-recovery.json'); F.writeExclusive(manifestFile, manifest); ctx = V.loadVortex(manifestFile, abiFile);
  const next = await prepare('unpause', {}, true); next.signed = await signatures(next, 2); await startProducer(); await submit(next.signed); await pauseProducer();
  const proposalHash = (await V.reviewPackage(ctx, V.readPackage(next.signed))).action.proposalHash;
  const cancel = await prepare('cancel', { actionHash: proposalHash }); cancel.signed = await signatures(cancel, 2); await startProducer(); await check('installed administrator cancellation consumes the exact ordinary proposal', () => submit(cancel.signed)); await pauseProducer();
  const expiring = await prepare('unpause', {}, true); expiring.signed = await signatures(expiring, 2);
  await startProducer(); await submit(expiring.signed); await pauseProducer(); await control('mine', 62, 259200001);
  await check('CLI and actual contract refuse expired execution without resetting the delay', async () => {
    const refusal = await prepare('unpause', {}, false, true); assert.match(refusal.stderr, /expired/);
    await raw('unpause'); assert.match(await control('execute'), /REFUSED proposal expired/);
  });
  await check('source and both installed paths expose the same commands/version', async () => {
    for (const argv of [[cli, '--version'], ['/opt/homebrew/bin/kcli', '--version'], [process.execPath, 'dist/index.js', '--version']]) { const r = spawnSync(argv[0], argv.slice(1), { cwd: root, env: { ...process.env, HOME: home }, encoding: 'utf8' }); assert.equal(r.status, 0); assert.equal(r.stdout.trim(), require('../package.json').version); }
  });
  writeEvidence(); console.log('LOCAL CONTRACT EXERCISE PASS: ' + results.length + ' checks');
})().catch(error => {
  writeEvidence(error); console.error('Local exercise incomplete: ' + error.message); process.exitCode = 1;
}).finally(async () => {
  if (relayServer) await new Promise(resolve => relayServer.close(resolve));
  // Stop only this run's containers. Retain evidence/volumes; no other namespace is modified.
  for (const name of ['producer', 'controller', 'jsonrpc', 'meta-store', 'tx-store', 'chain', 'block-store', 'mempool', 'amqp']) await docker('stop', runId + '-' + name);
  console.log('Stopped only ' + runId + '; synthetic evidence retained at ' + dir);
});
