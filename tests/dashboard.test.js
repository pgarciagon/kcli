const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { Contract, Provider } = require('koilib');
const tokenAbi = require('../src/abis/token.json');
const { DashboardProvider, DashboardReadCache, DashboardRpcError, parseDashboardInteger } = require('../dist/dashboard-rpc');
const { DashboardProducerData, dashboardValue, dashboardWholeUnits } = require('../dist/dashboard-data');
const { createDashboardRpc, CHAIN_ID, KOIN, VHP, OWNERS, sleep } = require('./dashboard-fixture');

async function withRpc(t, options = {}, providerOptions = {}) {
  const rpc = await createDashboardRpc(options);
  const provider = new DashboardProvider(rpc.url, { backoffMs: 5, idleSocketMs: 50, ...providerOptions });
  t.after(async () => { provider.close(); await rpc.close(); });
  return { rpc, provider };
}

async function drainData(data, specs) {
  for (const spec of specs) await data.cache.refresh(data.cache.key(spec));
}

async function runCli(rpc, args, durationMs = 2200, command = process.execPath, prefix = [path.resolve('dist/index.js')]) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'kcli-dashboard-test-'));
  const child = spawn(command, [...prefix, '--network', 'mainnet', '--rpc', rpc.url, 'producer-dashboard', '--window', '8', '--top', '4', '--interval', '1', ...args], {
    env: { ...process.env, HOME: home, KOINOS_BASEDIR: home }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  let ready = false;
  let timer = setTimeout(() => child.kill('SIGTERM'), 10000);
  child.stdout.on('data', chunk => {
    output += chunk;
    if (!ready && output.includes('Updated:')) {
      ready = true;
      clearTimeout(timer);
      timer = setTimeout(() => child.kill('SIGTERM'), durationMs);
    }
  });
  child.stderr.on('data', chunk => output += chunk);
  try {
    const code = await new Promise((resolve, reject) => { child.once('exit', resolve); child.once('error', reject); });
    return { code, output };
  } finally { clearTimeout(timer); child.kill('SIGTERM'); fs.rmSync(home, { recursive: true, force: true }); }
}

test('dashboard bounds real sockets and requests, reuses connections and releases idle sessions', async t => {
  const { rpc, provider } = await withRpc(t, { delayMs: 20 }, { maxQueue: 32, idleSocketMs: 100 });
  await Promise.all(Array.from({ length: 16 }, (_, index) => provider.call('chain.get_head_info', { index })));
  assert.equal(rpc.calls.length, 16);
  assert.equal(rpc.metrics.errors, 0);
  assert.equal(rpc.metrics.peakSockets, 2);
  assert.equal(rpc.metrics.maxActive, 2);
  assert.equal(rpc.metrics.connections, 2);
  assert.equal(provider.metrics.maxSockets, 2);
  await sleep(160);
  assert.equal(rpc.openSockets(), 0);
});

test('raw koilib concurrency reproduces a four-session overload, unlike dashboard provider', async t => {
  const rpc = await createDashboardRpc({ delayMs: 30 });
  t.after(() => rpc.close());
  const provider = new Provider(rpc.url);
  const results = await Promise.allSettled(Array.from({ length: 12 }, (_, index) => provider.call('chain.get_head_info', { index })));
  assert.ok(results.some(result => result.status === 'rejected'));
  assert.ok(rpc.metrics.errors > 0);
  assert.ok(rpc.metrics.peakSockets > 4);
  t.diagnostic(`Unbounded koilib: ${rpc.metrics.peakSockets} peak sockets, ${rpc.metrics.errors} session errors for 12 reads`);
});

test('RPC in-flight deduplication includes canonical method arguments', async t => {
  const { rpc, provider } = await withRpc(t);
  const first = provider.call('chain.get_head_info', { a: 1, b: 2 });
  const second = provider.call('chain.get_head_info', { b: 2, a: 1 });
  assert.equal(first, second);
  await Promise.all([first, second]);
  assert.equal(rpc.calls.length, 1);
});

test('recoverable HTTP 503 reads use bounded backoff and recover', async t => {
  const { rpc, provider } = await withRpc(t, { override: (_, calls) => calls.length < 3 ? { error: 'JSON-RPC session limit reached', status: 503 } : undefined });
  assert.equal((await provider.getHeadInfo()).head_topology.height, '120');
  assert.equal(rpc.calls.length, 3);
  assert.equal(provider.metrics.retries, 2);
});

test('nonrecoverable contract errors are not retried and do not expose RPC messages', async t => {
  const { rpc, provider } = await withRpc(t, { override: () => ({ error: '\u001b[31mprivate diagnostic\nsecret', code: -1 }) });
  await assert.rejects(provider.getHeadInfo(), /RPC read failed \(code -1\)/);
  assert.equal(rpc.calls.length, 1);
});

test('absolute timeout aborts slow reads and caps attempts', async t => {
  const { rpc, provider } = await withRpc(t, { override: () => ({ hang: true }) }, { timeoutMs: 40, retries: 1 });
  await assert.rejects(provider.getHeadInfo(), /timeout/);
  assert.equal(rpc.calls.length, 2);
  await sleep(30);
  assert.equal(rpc.openSockets(), 0);
});

test('RPC queue is bounded and writes are refused without network access', async t => {
  const { rpc, provider } = await withRpc(t, { delayMs: 30 }, { maxQueue: 2 });
  await assert.rejects(provider.call('chain.submit_transaction', {}), /read-only/);
  const results = await Promise.allSettled(Array.from({ length: 20 }, (_, index) => provider.call('chain.get_head_info', { index })));
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 4);
  assert.equal(rpc.calls.length, 4);
  assert.ok(rpc.metrics.maxActive <= 2);
});

test('cache keys isolate network, endpoint, contract, method and arguments', () => {
  const spec = { contract: KOIN, method: 'balance_of', args: { owner: OWNERS[0], a: 1 } };
  const cache = new DashboardReadCache('mainnet', 'http://127.0.0.1:123/');
  assert.equal(cache.key(spec), cache.key({ ...spec, args: { a: 1, owner: OWNERS[0] } }));
  for (const changed of [{ ...spec, contract: VHP }, { ...spec, method: 'total_supply' }, { ...spec, args: { owner: OWNERS[1] } }]) assert.notEqual(cache.key(spec), cache.key(changed));
  assert.notEqual(cache.key(spec), new DashboardReadCache('testnet', 'http://127.0.0.1:123/').key(spec));
  assert.notEqual(cache.key(spec), new DashboardReadCache('mainnet', 'http://127.0.0.1:124/').key(spec));
});

test('cache shares pending reads, preserves last success and recovers without unknown-to-zero conversion', async () => {
  let now = 1000, calls = 0, fail = false;
  const cache = new DashboardReadCache('mainnet', 'http://localhost:123/', 2, 150, () => now);
  const spec = { contract: KOIN, method: 'balance_of', args: {}, ttlMs: 30000, read: async () => { calls++; await sleep(5); if (fail) throw new DashboardRpcError('HTTP 503: session limit reached', true); return 7n; } };
  cache.setWanted([spec]);
  assert.equal(cache.peek(spec).value, undefined);
  const first = cache.refresh(cache.key(spec));
  assert.equal(first, cache.refresh(cache.key(spec)));
  await first;
  assert.equal(calls, 1);
  assert.equal(cache.peek(spec).updatedAt, 1000);
  now = 31000; fail = true;
  await cache.refresh(cache.key(spec));
  const stale = cache.peek(spec);
  assert.equal(stale.value, 7n);
  assert.equal(stale.updatedAt, 1000);
  assert.equal(stale.ageMs, 30000);
  assert.equal(stale.stale, true);
  assert.match(dashboardValue(stale, String), /stale:30s/);
  now = 36000; fail = false;
  await cache.refresh(cache.key(spec));
  assert.equal(cache.peek(spec).stale, false);
  assert.equal(cache.peek(spec).error, undefined);
  assert.equal(cache.peek(spec).updatedAt, 36000);
});

test('failed first read remains n/a, and cache cooldown does not poll every screen tick', async () => {
  let now = 0, calls = 0;
  const cache = new DashboardReadCache('mainnet', 'http://localhost:123/', 1, 150, () => now);
  const spec = { contract: OWNERS[0], method: 'get_pool_params', args: {}, ttlMs: 600000,
    read: async () => { calls++; throw new DashboardRpcError('RPC read failed (code -1)'); } };
  cache.setWanted([spec]);
  await cache.refresh(cache.key(spec));
  for (now = 5000; now < 30000; now += 5000) { cache.tick(); await sleep(1); }
  assert.equal(calls, 1);
  assert.equal(dashboardValue(cache.peek(spec), String), 'n/a');
});

test('scheduler staggers reads, never queues duplicate rounds, and abandons unwanted work', async () => {
  let now = 0, active = 0, peak = 0;
  const starts = [];
  const cache = new DashboardReadCache('mainnet', 'http://localhost:123/', 2, 150, () => now);
  const specs = Array.from({ length: 8 }, (_, index) => ({ contract: KOIN, method: 'balance_of', args: { index }, ttlMs: 30000,
    read: async () => { starts.push(now); active++; peak = Math.max(peak, active); await sleep(5); active--; return index; } }));
  cache.setWanted(specs);
  for (now = 0; now <= 2000; now += 50) { cache.tick(); cache.tick(); cache.setWanted(specs); await sleep(1); }
  assert.equal(starts.length, 8);
  assert.ok(starts.every((value, index) => !index || value - starts[index - 1] >= 150));
  assert.ok(peak <= 2);
  now = 40000;
  cache.setWanted([]); cache.tick(); await sleep(10);
  assert.equal(starts.length, 8);
});

test('inactive cache history is bounded and evicted without losing active entries', async () => {
  const cache = new DashboardReadCache('mainnet', 'http://localhost:123/', 1, 0, Date.now, 2);
  const spec = index => ({ contract: KOIN, method: 'balance_of', args: { index }, ttlMs: 30000, read: async () => index });
  cache.setWanted([spec(0), spec(1)]); await cache.refresh(cache.key(spec(0)));
  cache.setWanted([spec(0), spec(2)]);
  assert.equal(cache.peek(spec(0)).value, 0);
  await cache.refresh(cache.key(spec(2)));
  assert.equal(cache.peek(spec(2)).value, 2);
  assert.equal(cache.peek(spec(1)).value, undefined);
});

test('KOIN and VHP failures are independent, pool failures stay unknown, and incomplete APY stays n/a', async t => {
  const { provider } = await withRpc(t, { override: rpc => rpc.method === 'chain.read_contract' && rpc.params.contract_id === KOIN && rpc.params.entry_point === tokenAbi.methods.balance_of.entry_point
    ? { error: 'JSON-RPC session limit reached', status: 503 } : rpc.method === 'chain.read_contract' && rpc.params.contract_id === OWNERS[0] ? { error: 'Not a pool' } : undefined }, { retries: 0 });
  const data = new DashboardProducerData(provider, CHAIN_ID, KOIN, VHP);
  data.select(OWNERS.slice(0, 2), OWNERS.slice(0, 1));
  await drainData(data, [data.balanceSpec('koin', OWNERS[0]), data.balanceSpec('vhp', OWNERS[0]), data.supplySpec('koin'), data.supplySpec('vhp'), data.poolSpec(OWNERS[0])]);
  assert.equal(data.balance('koin', OWNERS[0]).value, undefined);
  assert.equal(data.balance('vhp', OWNERS[0]).value, 45600000000n);
  assert.equal(data.pool(OWNERS[0]).value, undefined);
  assert.equal(data.apy(OWNERS.slice(0, 2)).value, undefined);
  await drainData(data, [data.balanceSpec('vhp', OWNERS[1])]);
  assert.ok(data.apy(OWNERS.slice(0, 2)).value);
});

test('successful pool classification survives temporary failure and then recovers', async t => {
  const { rpc, provider } = await withRpc(t, {}, { retries: 0 });
  let now = 1000;
  const data = new DashboardProducerData(provider, CHAIN_ID, KOIN, VHP, 30000, 600000, () => now);
  data.select([OWNERS[0]], [OWNERS[0]]);
  await drainData(data, [data.poolSpec(OWNERS[0])]);
  now = 601000;
  rpc.state.override = rpc => rpc.params.contract_id === OWNERS[0] ? { error: 'JSON-RPC session limit reached', status: 503 } : undefined;
  await drainData(data, [data.poolSpec(OWNERS[0])]);
  assert.equal(data.pool(OWNERS[0]).value.name, 'Synthetic Pool');
  assert.equal(data.pool(OWNERS[0]).stale, true);
  rpc.state.override = undefined; now += 5000;
  await drainData(data, [data.poolSpec(OWNERS[0])]);
  assert.equal(data.pool(OWNERS[0]).stale, false);
});

test('failed VHP and supply reads preserve successful KOIN independently and prevent incomplete APY', async t => {
  const { provider } = await withRpc(t, { override: rpc => rpc.method === 'chain.read_contract' && rpc.params.contract_id === VHP
    ? { error: 'Temporary overload', status: 503 } : undefined }, { retries: 0 });
  const data = new DashboardProducerData(provider, CHAIN_ID, KOIN, VHP);
  data.select([OWNERS[0]], [OWNERS[0]]);
  await drainData(data, [data.balanceSpec('koin', OWNERS[0]), data.balanceSpec('vhp', OWNERS[0]), data.supplySpec('koin'), data.supplySpec('vhp')]);
  assert.equal(data.balance('koin', OWNERS[0]).value, 12300000000n);
  assert.equal(data.balance('vhp', OWNERS[0]).value, undefined);
  assert.equal(data.supply('koin').value, 100000000000000n);
  assert.equal(data.supply('vhp').value, undefined);
  assert.equal(data.apy([OWNERS[0]]).value, undefined);
});

test('complete cached APY is labeled stale with the oldest input age', async t => {
  const { rpc, provider } = await withRpc(t, {}, { retries: 0 });
  let now = 1000;
  const data = new DashboardProducerData(provider, CHAIN_ID, KOIN, VHP, 30000, 600000, () => now);
  data.select([OWNERS[0]], [OWNERS[0]]);
  await drainData(data, [data.balanceSpec('vhp', OWNERS[0]), data.supplySpec('koin'), data.supplySpec('vhp')]);
  const previous = data.apy([OWNERS[0]]).value;
  now = 32000;
  rpc.state.override = () => ({ error: 'Session limit reached', status: 503 });
  await drainData(data, [data.balanceSpec('vhp', OWNERS[0])]);
  const apy = data.apy([OWNERS[0]]);
  assert.equal(apy.value, previous);
  assert.equal(apy.stale, true);
  assert.equal(apy.ageMs, 31000);
  assert.match(dashboardValue(apy, String), /stale:31s/);
});

test('malformed or missing balances are not zero, but valid protobuf zero is zero', async t => {
  const { rpc, provider } = await withRpc(t, {}, { retries: 0 });
  const data = new DashboardProducerData(provider, CHAIN_ID, KOIN, VHP);
  data.select([OWNERS[0]], [OWNERS[0]]);
  rpc.state.override = () => ({ result: {} });
  await drainData(data, [data.balanceSpec('koin', OWNERS[0])]);
  assert.equal(data.balance('koin', OWNERS[0]).value, undefined);
  rpc.state.override = () => ({ result: { result: '' } });
  await drainData(data, [data.balanceSpec('koin', OWNERS[0])]);
  assert.equal(data.balance('koin', OWNERS[0]).value, 0n);
});

test('six five-second screen cycles reuse 30-second balances and 10-minute pool data', async t => {
  const { rpc, provider } = await withRpc(t);
  let now = 0;
  const owners = OWNERS.slice(0, 4);
  const data = new DashboardProducerData(provider, CHAIN_ID, KOIN, VHP, 30000, 600000, () => now, 0);
  data.select(owners, owners);
  const specs = owners.flatMap(owner => [data.balanceSpec('koin', owner), data.balanceSpec('vhp', owner), data.poolSpec(owner)]).concat(data.supplySpec('koin'), data.supplySpec('vhp'));
  await drainData(data, specs);
  assert.equal(rpc.calls.length, 14);
  for (now = 5000; now < 30000; now += 5000) { data.select(owners, owners); data.cache.tick(); await sleep(1); }
  assert.equal(rpc.calls.length, 14);
  t.diagnostic('Six screen cycles / four producers: 14 metadata reads versus 64 legacy reads (78.125% reduction; head/block reads excluded)');
  now = 30000;
  data.cache.tick(); await sleep(20);
  assert.equal(rpc.calls.length, 15);
});

test('normal koilib commands remain unchanged and do not inherit dashboard retry policy', async t => {
  const rpc = await createDashboardRpc({ override: () => ({ error: 'Synthetic failure' }) });
  t.after(() => rpc.close());
  const provider = new Provider(rpc.url);
  const contract = new Contract({ id: KOIN, abi: tokenAbi, provider });
  await assert.rejects(contract.functions.balance_of({ owner: OWNERS[0] }));
  assert.equal(rpc.calls.length, 1);
});

test('installed CLI renders independent balances, bounded warnings and RPC counters', async t => {
  const rpc = await createDashboardRpc({ producers: 1, override: rpc => rpc.method === 'chain.read_contract' && rpc.params.contract_id === KOIN && rpc.params.entry_point === tokenAbi.methods.balance_of.entry_point
    ? { error: 'JSON-RPC session limit reached', status: 503 } : undefined });
  t.after(() => rpc.close());
  const { code, output } = await runCli(rpc, ['--rpc-retries', '0', '--rpc-stats'], 2600, 'kcli', []);
  assert.equal(code, 0);
  assert.match(output, /session limit reached/);
  assert.match(output, /RPC stats:/);
  assert.match(output.split('\n').find(line => line.includes(OWNERS[0]) && line.includes('n/a')) || '', /n\/a\s+456/);
  assert.ok(rpc.metrics.peakSockets <= 2);
  assert.ok(rpc.metrics.maxActive <= 2);
});

test('slow RPC does not stall screen refreshes or accumulate activity requests', async t => {
  const rpc = await createDashboardRpc({ override: rpc => rpc.method === 'chain.get_head_info' ? { hang: true } : undefined });
  t.after(() => rpc.close());
  const { output } = await runCli(rpc, ['--rpc-timeout', '5', '--rpc-retries', '0'], 2400);
  assert.ok((output.match(/Updated:/g) || []).length >= 2);
  assert.equal(rpc.calls.filter(call => call.method === 'chain.get_head_info').length, 1);
  assert.equal(rpc.calls.filter(call => call.method === 'chain.read_contract').length, 0);
});

test('CLI retains last-good KOIN during transient failure, shows stale age and recovers', async t => {
  let koinReads = 0;
  const rpc = await createDashboardRpc({ producers: 1, override: rpc => {
    if (rpc.method === 'chain.read_contract' && rpc.params.contract_id === KOIN && rpc.params.entry_point === tokenAbi.methods.balance_of.entry_point && ++koinReads === 2) {
      return { error: 'JSON-RPC session limit reached', status: 503 };
    }
  } });
  t.after(() => rpc.close());
  const { code, output } = await runCli(rpc, ['--balance-interval', '1', '--rpc-retries', '0'], 4200);
  assert.equal(code, 0);
  const rows = output.split('\n').filter(line => line.includes(OWNERS[0]));
  assert.ok(rows.some(row => /123 stale:/.test(row) && /456/.test(row)));
  assert.ok(rows.length >= 3);
  assert.ok(!rows.at(-1).includes('123 stale:'));
  assert.ok(koinReads >= 3);
  assert.ok(rpc.metrics.peakSockets <= 2);
});

test('CLI retains producer activity and labels it stale after a later head failure', async t => {
  let heads = 0;
  const rpc = await createDashboardRpc({ producers: 1, override: rpc => rpc.method === 'chain.get_head_info' && ++heads > 1
    ? { error: 'JSON-RPC session limit reached', status: 503 } : undefined });
  t.after(() => rpc.close());
  const { output } = await runCli(rpc, ['--rpc-retries', '0'], 2400);
  assert.match(output, /Head Block: 120 \| Activity stale:/);
  assert.match(output, /activity stale:/);
  assert.ok(output.split('\n').filter(line => line.includes(OWNERS[0])).length >= 2);
});

test('wrong network blocks contract reads and CLI rejects unsafe tuning values', async t => {
  const rpc = await createDashboardRpc();
  t.after(() => rpc.close());
  rpc.state.chainId = 'wrong-network';
  const wrong = await runCli(rpc, [], 1300);
  assert.match(wrong.output, /RPC chain does not match selected network/);
  assert.equal(rpc.calls.filter(call => call.method === 'chain.read_contract').length, 0);
  const invalid = await runCli(rpc, ['--rpc-concurrency', '5']);
  assert.equal(invalid.code, 1);
  assert.equal(parseDashboardInteger('30', '--balance-interval', 3600), 30);
  for (const value of ['0', '-1', '1.5', '30x', '01', '9007199254740992']) {
    assert.throws(() => parseDashboardInteger(value, '--balance-interval', 3600), /must be an integer/);
  }
  const malformed = await runCli(rpc, ['--balance-interval', '30x']);
  assert.equal(malformed.code, 1);
  assert.match(malformed.output, /--balance-interval must be an integer/);
});

test('stale markers and ages survive long values without overflowing columns', () => {
  const text = dashboardValue({ value: 18446744073709551615n, stale: true, ageMs: 65000, loading: false }, dashboardWholeUnits);
  assert.ok(text.length <= 24);
  assert.match(text, /stale:1m5s$/);
});
