// Opt-in read-only comparison. Live baseline traffic is relayed through two bounded sockets.
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { DashboardProvider, DashboardRpcError } = require('../dist/dashboard-rpc');
const { createDashboardRpc, CHAIN_ID } = require('./dashboard-fixture');

async function run(url, entry, durationMs, stats) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'kcli-dashboard-measure-'));
  const args = ['--network', 'mainnet', '--rpc', url, 'producer-dashboard', '--window', '12', '--top', '4', '--interval', '5'];
  const command = entry === 'installed' ? 'kcli' : process.execPath;
  const child = spawn(command, [...(entry === 'installed' ? [] : [entry]), ...args, ...(stats ? ['--rpc-stats'] : [])], {
    env: { ...process.env, HOME: home, KOINOS_BASEDIR: home }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  child.stdout.on('data', chunk => output += chunk);
  child.stderr.on('data', chunk => output += chunk);
  const timer = setTimeout(() => child.kill('SIGTERM'), durationMs);
  try {
    const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', resolve); });
    const frames = output.split('\x1Bc').filter(frame => frame.includes('Koinos Producer Dashboard'));
    const metrics = [...output.matchAll(/RPC stats: (\{[^\n]+\})/g)].at(-1)?.[1];
    return { code, frames: frames.length, framesWithActivity: frames.filter(frame => /Head Block:/.test(frame)).length,
      warningFrames: frames.filter(frame => /Warning:|⚠️|Failed to refresh/.test(frame)).length,
      stats: metrics ? JSON.parse(metrics) : undefined };
  } finally { clearTimeout(timer); child.kill('SIGTERM'); fs.rmSync(home, { recursive: true, force: true }); }
}

async function relay(endpoint) {
  const url = new URL(endpoint);
  if (url.protocol !== 'http:' || !['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname) || url.username || url.password || url.search) {
    throw new Error('Live comparison requires an explicit credential-free loopback HTTP endpoint');
  }
  const provider = new DashboardProvider(endpoint, { concurrency: 2, maxQueue: 64, timeoutMs: 10000, retries: 0 });
  try {
    if (await provider.getChainId() !== CHAIN_ID) throw new Error('Live endpoint is not mainnet');
  } catch (error) { provider.close(); throw error; }
  const calls = [];
  let errors = 0;
  const server = http.createServer(async (request, response) => {
    try {
      let body = '';
      for await (const chunk of request) body += chunk;
      const rpc = JSON.parse(body);
      calls.push(rpc);
      response.setHeader('Content-Type', 'application/json');
      try {
        const result = await provider.call(rpc.method, rpc.params);
        response.end(JSON.stringify({ jsonrpc: '2.0', id: rpc.id, result }));
      } catch (error) {
        errors++;
        response.statusCode = error instanceof DashboardRpcError && error.recoverable ? 503 : 200;
        response.end(JSON.stringify({ jsonrpc: '2.0', id: rpc.id, error: { code: -1, message: error.message } }));
      }
    } catch { response.statusCode = 400; response.end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${server.address().port}/`, calls, provider,
    metrics: () => ({ errors, ...provider.metrics }),
    close: async () => { provider.close(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); } };
}

async function sample(entry, live, durationMs) {
  const rpc = live ? await relay(live) : await createDashboardRpc();
  try {
    const cli = await run(rpc.url, entry, durationMs, entry === 'installed');
    const byMethod = {};
    for (const call of rpc.calls) byMethod[call.method] = (byMethod[call.method] || 0) + 1;
    return { ...cli, calls: rpc.calls.length, contractReads: byMethod['chain.read_contract'] || 0,
      byMethod, transport: typeof rpc.metrics === 'function' ? rpc.metrics() : rpc.metrics };
  } finally { await rpc.close(); }
}

async function main() {
  const baseline = process.argv[2];
  if (!baseline || !fs.existsSync(baseline)) throw new Error('Pass the retained pre-change compiled CLI path');
  const live = process.argv[3];
  if (live && process.env.KCLI_DASHBOARD_LIVE_READS !== '1') throw new Error('Explicit KCLI_DASHBOARD_LIVE_READS=1 is required for live reads');
  const durationMs = 27000;
  const before = await sample(path.resolve(baseline), live, durationMs);
  const after = await sample('installed', live, durationMs);
  const comparable = before.byMethod['chain.get_head_info'] === after.byMethod['chain.get_head_info']
    && before.byMethod['block_store.get_blocks_by_height'] === after.byMethod['block_store.get_blocks_by_height'];
  console.log(JSON.stringify({ mode: live ? 'live-read-only-two-socket-relay' : 'four-session-simulated-RPC',
    durationMsPerRun: durationMs, screenIntervalMs: 5000, window: 12, top: 4, before, after,
    comparisonLimit: comparable ? null : 'Activity round counts differ; observed call counts are not an equivalent-workload reduction measurement',
    contractReadReductionPercent: comparable && before.contractReads ? Number((100 * (1 - after.contractReads / before.contractReads)).toFixed(2)) : null,
    totalReadReductionPercent: comparable && before.calls ? Number((100 * (1 - after.calls / before.calls)).toFixed(2)) : null }, null, 2));
}

if (require.main === module) main().catch(error => { console.error(error.message); process.exitCode = 1; });
module.exports = { run, sample };
