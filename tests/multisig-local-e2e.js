// Opt-in installed-CLI exercise on a NEW disposable local chain (never part of `npm test`, never a public chain).
// Follows the foundation operating guide with synthetic members in separate HOME directories and hidden PTY
// passwords. usage: node multisig-local-e2e.js <deploy|operate> <work dir> <loopback rpc>
// Also used for the separately authorized official-testnet rehearsal: NETWORK=testnet with its HTTPS RPC.
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
// Staged in the per-run workspace; the candidate kcli checkout is given explicitly and never modified.
const ROOT = process.env.KCLI_ROOT; assert(ROOT && fs.existsSync(path.join(ROOT, 'dist', 'multisig-protocol.js')), 'set KCLI_ROOT to the installed candidate checkout');
const { Contract, Provider } = require(path.join(ROOT, 'node_modules', 'koilib'));
const MP = require(path.join(ROOT, 'dist', 'multisig-protocol'));
const [phase, W, rpc] = process.argv.slice(2);
const NETWORK = process.env.NETWORK || 'local';
const RPC_OK = NETWORK === 'testnet' ? rpc === 'https://testnet.koinosfoundation.org/jsonrpc' : /^http:\/\/127\.0\.0\.1:\d+\/$/.test(rpc);
assert(['deploy', 'operate'].includes(phase) && W && RPC_OK, 'usage: <deploy|operate> <work dir> <rpc> (loopback for local; the official testnet RPC with NETWORK=testnet)');
// Testnet: frugal amounts, measured RC limits from the environment, waits sized for ~60-block irreversibility.
const T = NETWORK === 'testnet' ? { pay1: '0.5', pay1Raw: '50000000', pay2: '0.1', pay2Raw: '10000000', minBalance: 500000000n, wait: '600', timeout: '120' }
  : { pay1: '12.5', pay1Raw: '1250000000', pay2: '1', pay2Raw: '100000000', minBalance: 100000000000n, wait: '300', timeout: '20' };
const DEPLOY_RC = process.env.DEPLOY_RC || '100000000', CALL_RC = process.env.CALL_RC || '10000000';
const password = 'synthetic-exercise-only-password';
const keys = JSON.parse(fs.readFileSync(path.join(W, 'keys.json'), 'utf8'));
const evidenceFile = path.join(W, 'evidence-cli.json');
const evidence = fs.existsSync(evidenceFile) ? JSON.parse(fs.readFileSync(evidenceFile, 'utf8')) : { schema: 1, networkProfile: process.env.NETWORK || 'local', publicChainUsed: process.env.NETWORK === 'testnet', syntheticOnly: true, independentCustody: false, steps: [] };
const record = (name, data = {}) => { evidence.steps.push({ name, ...data }); fs.writeFileSync(evidenceFile, JSON.stringify(evidence, null, 2), { mode: 0o600 }); console.log('PASS ' + name); };
const home = name => { const d = path.join(W, 'homes', name); fs.mkdirSync(d, { recursive: true, mode: 0o700 }); fs.chmodSync(d, 0o700); return d; };
const coordinator = home('coordinator');
const memberHome = i => home('member-' + i);
const docs = out => out.split(/\n(?=\{)/).filter(Boolean).map(x => JSON.parse(x));
function kcli(h, argv, expect = 0) {
  const r = spawnSync('kcli', argv, { cwd: W, encoding: 'utf8', env: { ...process.env, HOME: h }, timeout: 1500000 });
  assert.equal(r.status, expect, `kcli ${argv.slice(0, 2).join(' ')} exited ${r.status}: ${r.stderr}`);
  if (expect === 0) return docs(r.stdout);
  return r.stderr;
}
function pty(h, argv, inputs) {
  const r = spawnSync('python3', [path.join(ROOT, 'tests', 'vortex-pty.py')], { input: JSON.stringify({ home: h, argv: ['kcli', ...argv], inputs }), encoding: 'utf8', timeout: 400000, cwd: W });
  const reply = JSON.parse(r.stdout); assert.equal(reply.leaked, false, 'synthetic secret escaped terminal output');
  assert.equal(reply.status, 0, 'kcli failed under PTY: ' + reply.stdout.slice(-600)); return reply;
}
const importWallet = (h, name, wif) => pty(h, ['wallets', 'import', name], [{ prompt: 'Import WIF (hidden): ', value: wif }, { prompt: 'New wallet password: ', value: password }, { prompt: 'Confirm wallet password: ', value: password }]);
const online = ['--network', NETWORK, '--rpc', rpc];
async function koinBalance(address) {
  const provider = new Provider(rpc); const c = new Contract({ id: keys.koin, abi: MP.KOIN_ABI, provider });
  const { result } = await c.functions.balance_of({ owner: address }); return BigInt(result?.value || '0');
}
function memberSign(i, file, manifest, id, signer = keys.owners[i]) {
  const local = path.join(memberHome(i), path.basename(file)); fs.copyFileSync(file, local);
  const review = kcli(memberHome(i), ['multisig', 'inspect', local, '--manifest', manifest])[0];
  assert.equal(review.id, id, 'member sees the same exact ID');
  const out = path.join(W, path.basename(file, '.json') + `.member-${i}.json`);
  pty(memberHome(i), ['multisig', 'sign', local, '--manifest', manifest, '--wallet', 'member', '--signer', signer.address, '--id', id, '--out', out], [{ prompt: 'Wallet password: ', value: password }]);
  return out;
}

async function deploy() {
  importWallet(coordinator, 'treasury-bootstrap', keys.treasury.wif);
  keys.owners.forEach((o, i) => importWallet(memberHome(i), 'member', o.wif));
  importWallet(memberHome(5), 'member', keys.future.wif);
  record('wallets: bootstrap key and six members imported into separate HOMEs through hidden PTY input');

  const artifact = path.join(W, 'artifact');
  const prepared = kcli(coordinator, ['multisig', 'prepare-deploy', '--artifact', artifact, ...online, '--rc-limit', DEPLOY_RC, '--out', path.join(W, 'deploy.json')])[0];
  assert.equal(prepared.status, 'prepared'); assert.deepEqual(prepared.owners, keys.owners.map(o => o.address)); assert.deepEqual(prepared.flags, { call: true, transaction: true, upload: true });
  const inspected = kcli(coordinator, ['multisig', 'inspect-deploy', path.join(W, 'deploy.json')])[0]; assert.equal(inspected.id, prepared.id);
  record('prepare-deploy + inspect-deploy: unused address checked, single upload with all three flags, exact artifact hashes', { bootstrapId: prepared.id, wasmSha256: prepared.wasmSha256 });

  const wrong = kcli(memberHome(0), ['multisig', 'sign-deploy', path.join(W, 'deploy.json'), '--wallet', 'member', '--signer', keys.owners[0].address, '--id', prepared.id, '--out', path.join(W, 'x.json')], 1);
  assert.match(wrong, /treasury address/);
  pty(coordinator, ['multisig', 'sign-deploy', path.join(W, 'deploy.json'), '--wallet', 'treasury-bootstrap', '--signer', keys.treasury.address, '--id', prepared.id, '--out', path.join(W, 'deploy.signed.json')], [{ prompt: 'Wallet password: ', value: password }]);
  const dry = kcli(coordinator, ['multisig', 'submit-deploy', path.join(W, 'deploy.signed.json'), ...online, '--dry-run'])[0]; assert.equal(dry.preflight, 'passed'); assert.equal(dry.submitted, false);
  const sent = kcli(coordinator, ['multisig', 'submit-deploy', path.join(W, 'deploy.signed.json'), ...online, '--id', prepared.id, '--wait', T.wait])[0];
  assert.equal(sent.status, 'irreversible');
  record('sign-deploy (member key refused) + submit-deploy dry-run + one exact submission, irreversible', { block: sent.block, height: sent.height });

  const verified = kcli(coordinator, ['multisig', 'verify-deployment', path.join(W, 'deploy.signed.json'), ...online, '--wait', '600', '--timeout', '120', '--manifest-out', path.join(W, 'treasury.json')])[0];
  assert.equal(verified.status, 'deployment-verified');
  assert.equal(verified.checks.policySpaceEmpty, true); assert.equal(verified.checks.nonce, '1'); assert.equal(verified.checks.allowances, 0); assert.deepEqual(verified.checks.flags, { call: true, transaction: true, upload: true, system: false });
  record('verify-deployment: code + metadata hash, flags, empty policy space, policy v0, nonce 1, no allowances, read at one block that then became irreversible -> manifest written', { manifestSha256: verified.manifestSha256 });
  const again = kcli(coordinator, ['multisig', 'submit-deploy', path.join(W, 'deploy.signed.json'), ...online, '--id', prepared.id], 1);
  assert.match(again, /already paid|intent|contract/);
  record('a second bootstrap submission is refused');
}

async function operate() {
  const manifest = path.join(W, 'treasury.json'); const t = keys.treasury.address;
  const info = kcli(coordinator, ['multisig', 'info', '--manifest', manifest, ...online])[0];
  assert.equal(info.policy.version, '0'); assert(BigInt(info.balance) >= T.minBalance, 'funded after verification');
  record('info: verified code/flags/policy; balance and Mana read', { balance: info.balance, mana: info.mana, nonce: info.nonce });

  // Payment 1: 12.5 KOIN, three of five members on their own HOMEs.
  const before = await koinBalance(keys.recipient.address);
  const p1 = kcli(coordinator, ['multisig', 'prepare-transfer', '--manifest', manifest, ...online, '--to', keys.recipient.address, '--amount', T.pay1, '--rc-limit', CALL_RC, '--note', 'invoice e2e-1', '--out', path.join(W, 'payment-1.json')])[0];
  assert.equal(p1.action.amount, T.pay1); assert.equal(p1.action.raw, T.pay1Raw); assert.equal(p1.status, 'prepared'); assert.equal(p1.note.signed, false);
  const refusedOutsider = kcli(memberHome(5), ['multisig', 'sign', path.join(W, 'payment-1.json'), '--manifest', manifest, '--wallet', 'member', '--signer', keys.future.address, '--id', p1.id, '--out', path.join(W, 'y.json')], 1);
  assert.match(refusedOutsider, /not a current owner/);
  const signed = [0, 1, 2].map(i => memberSign(i, path.join(W, 'payment-1.json'), manifest, p1.id));
  const partial = kcli(coordinator, ['multisig', 'merge', signed[0], signed[1], '--manifest', manifest, '--out', path.join(W, 'payment-1.partial.json')])[0]; assert.equal(partial.status, 'partial');
  const tooFew = kcli(coordinator, ['multisig', 'submit', path.join(W, 'payment-1.partial.json'), '--manifest', manifest, ...online, '--dry-run'], 1); assert.match(tooFew, /Missing owner approvals/);
  const merged = kcli(coordinator, ['multisig', 'merge', ...signed, '--manifest', manifest, '--out', path.join(W, 'payment-1.approved.json')])[0]; assert.equal(merged.status, 'quorum-ready');
  const dry = kcli(coordinator, ['multisig', 'submit', path.join(W, 'payment-1.approved.json'), '--manifest', manifest, ...online, '--dry-run']); assert.equal(dry[1].submitted, false);
  // A short read timeout with a long wait: waiting for finality must extend the command deadline.
  const done = kcli(coordinator, ['multisig', 'submit', path.join(W, 'payment-1.approved.json'), '--manifest', manifest, ...online, '--id', p1.id, '--timeout', T.timeout, '--wait', T.wait])[0];
  assert.equal(done.status, 'irreversible-and-verified'); assert.equal(done.transferEvent.to, keys.recipient.address); assert.equal(done.transferEvent.value, T.pay1Raw);
  assert.equal(await koinBalance(keys.recipient.address) - before, BigInt(T.pay1Raw));
  const resend = kcli(coordinator, ['multisig', 'submit', path.join(W, 'payment-1.approved.json'), '--manifest', manifest, ...online, '--id', p1.id], 1); assert.match(resend, /stale or already used|intent/);
  const rec = kcli(coordinator, ['multisig', 'reconcile', path.join(W, 'payment-1.approved.json'), '--manifest', manifest, ...online])[0]; assert.equal(rec.status, 'irreversible-and-verified');
  record('payment: prepare, non-owner refused, 3 independent member signatures, partial refused, merge, dry-run, one submit, irreversible + event verified, resend refused, reconcile', { id: p1.id, block: done.block, recipientCredit: T.pay1 });

  // Rotation: replace member 0 by the future member, threshold 3 of 5, approved by the CURRENT quorum.
  const nextOwners = [...keys.owners.slice(1).map(o => o.address), keys.future.address];
  fs.writeFileSync(path.join(W, 'policy.json'), JSON.stringify({ owners: nextOwners, threshold: 3 }), { mode: 0o600 });
  const pp = kcli(coordinator, ['multisig', 'prepare-policy', '--manifest', manifest, ...online, '--policy', path.join(W, 'policy.json'), '--rc-limit', CALL_RC, '--out', path.join(W, 'policy-1.json')])[0];
  assert.equal(pp.action.kind, 'policy'); assert.deepEqual(pp.action.owners, MP.canonicalOwners(nextOwners));
  const ps = [0, 3, 4].map(i => memberSign(i, path.join(W, 'policy-1.json'), manifest, pp.id));
  const pm = kcli(coordinator, ['multisig', 'merge', ...ps, '--manifest', manifest, '--out', path.join(W, 'policy-1.approved.json')])[0]; assert.equal(pm.status, 'quorum-ready');
  const pdry = kcli(coordinator, ['multisig', 'submit', path.join(W, 'policy-1.approved.json'), '--manifest', manifest, ...online, '--dry-run']); assert.equal(pdry[1].submitted, false);
  const rotated = kcli(coordinator, ['multisig', 'submit', path.join(W, 'policy-1.approved.json'), '--manifest', manifest, ...online, '--id', pp.id, '--wait', T.wait])[0];
  assert.equal(rotated.status, 'irreversible-and-verified'); assert.equal(rotated.policy.version, '1');
  const noOut = kcli(coordinator, ['multisig', 'reconcile', path.join(W, 'policy-1.approved.json'), '--manifest', manifest, ...online], 1); assert.match(noOut, /manifest-out/);
  const snap = kcli(coordinator, ['multisig', 'reconcile', path.join(W, 'policy-1.approved.json'), '--manifest', manifest, ...online, '--manifest-out', path.join(W, 'treasury-v1.json')])[0];
  assert.equal(snap.status, 'irreversible-and-verified');
  const stale = kcli(coordinator, ['multisig', 'info', '--manifest', manifest, ...online], 1); assert.match(stale, /policy differs/);
  const stalePrepare = kcli(coordinator, ['multisig', 'prepare-transfer', '--manifest', manifest, ...online, '--to', keys.recipient.address, '--amount', T.pay2, '--rc-limit', CALL_RC, '--dry-run'], 1); assert.match(stalePrepare, /policy differs/);
  const v1 = path.join(W, 'treasury-v1.json'); const info1 = kcli(coordinator, ['multisig', 'info', '--manifest', v1, ...online])[0]; assert.equal(info1.policy.version, '1');
  record('rotation: replacement approved by the old quorum (merge quorum-ready, dry-run), irreversible, new manifest snapshot; old manifest refused for info and prepare', { id: pp.id, manifestSha256: snap.manifestSha256 });

  // Payment 2 under the new policy: the removed member cannot sign, the new member can.
  const p2 = kcli(coordinator, ['multisig', 'prepare-transfer', '--manifest', v1, ...online, '--to', keys.recipient.address, '--amount', T.pay2, '--rc-limit', CALL_RC, '--out', path.join(W, 'payment-2.json')])[0];
  const removed = kcli(memberHome(0), ['multisig', 'sign', path.join(W, 'payment-2.json'), '--manifest', v1, '--wallet', 'member', '--signer', keys.owners[0].address, '--id', p2.id, '--out', path.join(W, 'z.json')], 1);
  assert.match(removed, /not a current owner/);
  const s2 = [memberSign(5, path.join(W, 'payment-2.json'), v1, p2.id, keys.future), memberSign(3, path.join(W, 'payment-2.json'), v1, p2.id), memberSign(4, path.join(W, 'payment-2.json'), v1, p2.id)];
  const m2 = kcli(coordinator, ['multisig', 'merge', ...s2, '--manifest', v1, '--out', path.join(W, 'payment-2.approved.json')])[0]; assert.equal(m2.status, 'quorum-ready');
  const dry2 = kcli(coordinator, ['multisig', 'submit', path.join(W, 'payment-2.approved.json'), '--manifest', v1, ...online, '--dry-run']); assert.equal(dry2[1].submitted, false);
  const done2 = kcli(coordinator, ['multisig', 'submit', path.join(W, 'payment-2.approved.json'), '--manifest', v1, ...online, '--id', p2.id, '--wait', T.wait])[0];
  assert.equal(done2.status, 'irreversible-and-verified'); assert.equal(done2.transferEvent.value, T.pay2Raw);
  assert.equal(kcli(coordinator, ['multisig', 'reconcile', path.join(W, 'payment-2.approved.json'), '--manifest', v1, ...online])[0].status, 'irreversible-and-verified');
  const crossManifest = kcli(coordinator, ['multisig', 'inspect', path.join(W, 'payment-1.json'), '--manifest', v1], 1); assert.match(crossManifest, /different manifest/);
  record('post-rotation payment: removed member refused, new quorum (incl. new member) merges, dry-runs, pays and reconciles; old packages bind the old manifest', { id: p2.id });
  void t;
}
(phase === 'deploy' ? deploy() : operate()).then(() => console.log(phase.toUpperCase() + ' COMPLETE')).catch(e => { console.error('CLI exercise failed: ' + String(e.message).replace(/\b[5KL][1-9A-HJ-NP-Za-km-z]{49,51}\b/g, '[redacted-key]').slice(0, 1500)); process.exit(1); });
