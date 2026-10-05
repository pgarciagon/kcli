// Only runs in the fresh internal Docker network with the exact public laboratory genesis.
const fs = require('node:fs');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { LocalKoinos, Contract, Signer, utils } = require('/work/driver/node_modules/@roamin/local-koinos');
const lk = new LocalKoinos({ rpc: 'http://jsonrpc:8080/', amqp: 'amqp://guest:guest@amqp:5672' });
const stateDir = '/exercise';
let phase = 'chain-identity';
const expectedChain = 'EiD3i3yxv2aEUIbat5bRSakYgKqim9RCQ0B1w8DMvaCrWw==';
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const random = () => new Signer({ privateKey: crypto.randomBytes(32).toString('hex') });
const abiPath = '/work/fresh-build-release/bridge/abi/bridge.abi';
const bytecodePath = '/work/fresh-build-release/bridge/build/release/contract.wasm';
function normalized(text) {
  const a = JSON.parse(text); a.koilib_types = a.types;
  for (const m of Object.values(a.methods)) { m.entry_point = Number(m['entry-point']); m.read_only = m['read-only']; }
  return a;
}
async function headTime() { return BigInt((await lk.provider.getHeadInfo()).head_block_time || '0'); }
async function mine(count, jump = 0n) {
  // Start in the past so the real node's future-time guard remains enabled while
  // the harness advances several full 48-hour contract delays.
  let now = await headTime(); if (now === 0n) now = BigInt(Date.now()) - 14n * 86400000n; now += jump;
  for (let i = 0; i < count; i++) await lk.produceBlock({ logs: false, blockHeader: { timestamp: (++now).toString() } });
}
async function send(ops, signers = []) {
  const payer = lk.genesisSigner;
  const tx = await payer.prepareTransaction({ header: { payer: payer.address, rc_limit: '300000000' }, operations: ops });
  for (const s of [payer, ...signers]) await s.signTransaction(tx);
  const result = await lk.provider.sendTransaction(tx, true); assert(!result.receipt.reverted); await mine(62); return tx.id;
}
async function bootstrap() {
  phase = 'bootstrap-input';
  const input = JSON.parse(fs.readFileSync(stateDir + '/input.json'));
  assert.equal(input.admins.length, 3); assert.equal(new Set([...input.admins, input.payer]).size, 4);
  assert(!fs.existsSync(stateDir + '/deployment.json'), 'refuse repeated bootstrap');
  phase = 'reviewed-artifacts'; const bytecode = fs.readFileSync(bytecodePath);
  assert.equal(sha(bytecode), 'd66facf63456ff6b2690d7e6756142008b11d985886d8ce10411864eb6992a49', 'exact 48-hour candidate build required');
  const source = fs.readFileSync('/work/fresh-build-release/bridge/assembly/Bridge.ts', 'utf8');
  assert(source.includes('const ADMIN_DELAY_MS: u64 = 2 * DAY_MS;'));
  assert.equal(sha(source), 'aeaf0281e986505f400ed24e83a8cc49e193d16e03c13057b828ccfd93070411', 'reviewed fresh-initializer derivative source');
  phase = 'first-block'; await mine(1);
  phase = 'local-token-deployment';
  const tokenKey = lk.koin.signer;
  const tokenAbi = JSON.parse(fs.readFileSync('/work/kca-4fc33bb/contracts/koin/abi/koin.abi'));
  const token = new Contract({ id: tokenKey.address, abi: tokenAbi, provider: lk.provider, signer: tokenKey, bytecode: fs.readFileSync('/work/kca-4fc33bb/contracts/koin/build/testnet/contract.wasm') });
  const flags = { authorizesCallContract: true, authorizesTransactionApplication: true, authorizesUploadContract: true };
  await send([(await token.deploy({ abi: JSON.stringify(tokenAbi), ...flags, onlyOperation: true })).operation], [tokenKey]);
  phase = 'local-token-authority';
  await send([{ set_system_contract: { contract_id: tokenKey.address, system_contract: true } }]);
  phase = 'synthetic-payer-funding';
  await send([(await token.functions.mint({ to: input.payer, value: '100000000000000' }, { onlyOperation: true })).operation], [tokenKey]);
  const key = random(); const validators = [random(), random(), random()].map(s => s.address);
  const abiText = fs.readFileSync(abiPath, 'utf8'); const bridge = new Contract({ id: key.address, abi: normalized(abiText), provider: lk.provider, signer: key, bytecode });
  const upload = (await bridge.deploy({ abi: abiText, ...flags, onlyOperation: true })).operation;
  const initialize = (await bridge.functions.initialize_fresh({ validators, admins: input.admins, admin_threshold: 2, recovery_threshold: 3, eth_bridge: '0x' + '11'.repeat(20), eth_chain: 2, chain: 1 }, { onlyOperation: true })).operation;
  phase = 'bridge-initialization'; await send([upload, initialize], [key]);
  assert(await headTime() < BigInt(Date.now()) - 7n * 86400000n, 'bootstrap must preserve past-time origin');
  const deployment = { schema: 1, bridge: key.address, validators, recoveryValidators: [random(), random(), random()].map(s => s.address), codeSha256: sha(bytecode), abiSha256: sha(abiText), sourceSha256: sha(source), abiPath: 'bridge.abi', chainId: expectedChain };
  fs.writeFileSync(stateDir + '/bridge.abi', abiText, { mode: 0o600 }); fs.writeFileSync(stateDir + '/deployment.json', JSON.stringify(deployment, null, 2), { mode: 0o600 });
  console.log('PASS fresh Koinos bridge initialization with 48-hour contract delay');
}
async function execute() {
  const tx = JSON.parse(fs.readFileSync(stateDir + '/raw-transaction.json'));
  try {
    const { receipt } = await lk.provider.sendTransaction(tx, true);
    if (receipt.reverted) throw Error('contract reverted');
    await mine(62); console.log('ACCEPTED');
  } catch (error) {
    const message = String(error.message);
    // Only a bounded expected contract refusal, never a raw transaction/RPC log.
    const known = ['admin threshold not met', 'recovery threshold not met', 'time lock not expired', 'proposal expired', 'action not proposed', 'invalid nonce', 'nonce'];
    const reason = known.find(r => message.includes(r));
    if (!reason) throw Error('Unexpected local contract/transport failure; raw details withheld');
    console.log('REFUSED ' + reason);
  }
}
async function producer() {
  for (;;) {
    const pending = await lk.provider.call('mempool.get_pending_transactions', { limit: '1' });
    // Hold a stable head during multi-read preflight through the slow Docker relay.
    // Mine only after an explicit submission, then advance through real LIB finality.
    if (pending.pending_transactions?.length) await mine(62);
    await new Promise(r => setTimeout(r, 200));
  }
}
async function relay() {
  const chunks = []; let length = 0;
  for await (const chunk of process.stdin) { length += chunk.length; assert(length <= 1048576); chunks.push(chunk); }
  const body = Buffer.concat(chunks).toString('utf8');
  const response = await fetch('http://jsonrpc:8080/', { method: 'POST', headers: { 'content-type': 'application/json' }, body, redirect: 'error', signal: AbortSignal.timeout(10000) });
  const text = await response.text(); assert(text.length <= 1048576);
  await new Promise((resolve, reject) => process.stdout.write(text, error => error ? reject(error) : resolve()));
}
(async () => {
  await lk.awaitChain(); assert.equal(await lk.provider.getChainId(), expectedChain, 'public chains prohibited');
  switch (process.argv[2]) {
    case 'bootstrap': await bootstrap(); break;
    case 'mine': await mine(Number(process.argv[3] || 62), BigInt(process.argv[4] || 0)); console.log('MINED'); break;
    case 'execute': await execute(); break;
    case 'producer': await producer(); break;
    case 'relay': await relay(); break;
    default: throw Error('unsupported local controller action');
  }
})().then(() => process.exit(0)).catch(error => {
  const classes = ['TypeError', 'AssertionError', 'Error'];
  const known = ['insufficient rc', 'unable to consume rc', 'insufficient resource', 'not authorized', 'authorization failure', 'nonce', 'exit error did not contain error data', 'rc limit', 'resource limit', 'admin threshold', 'bad or duplicate', 'existing configuration', 'signed by the bridge account key'];
  const reason = known.find(r => String(error.message).toLowerCase().includes(r)) || 'unclassified';
  const diagnostic = String(error.message).replace(/\b[5KL][1-9A-HJ-NP-Za-km-z]{49,51}\b/g, '[redacted-key]').replace(/\b(?:0x)?[0-9a-fA-F]{64,}\b/g, '[redacted-digest]').replace(/[\x00-\x1f\x7f-\x9f]/g, ' ').slice(0, 500);
  console.error('Local chain exercise failed at ' + phase + ' (' + (classes.includes(error.name) ? error.name : 'error') + ', ' + reason + '): ' + diagnostic); process.exit(1);
});
