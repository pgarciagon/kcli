const http = require('node:http');
const { Signer, Serializer, utils } = require('koilib');
const tokenAbi = require('../src/abis/token.json');
const fogataAbi = require('../src/abis/fogata.json');

const CHAIN_ID = 'EiBZK_GGVP0H_fXVAM3j6EAuz3-B-l3ejxRSewi7qIBfSA==';
const KOIN = '19GYjDBVXU7keLbYvMLazsGQn3GTWHjHkK';
const VHP = '12Y5vW6gk8GceH53YfRkRre2Rrcsgw7Naq';
const OWNERS = Array.from({ length: 8 }, (_, index) => Signer.fromSeed(`dashboard synthetic owner ${index}; no real funds`).getAddress());
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function createDashboardRpc(options = {}) {
  const token = new Serializer(tokenAbi.koilib_types);
  const fogata = new Serializer(fogataAbi.koilib_types);
  const sockets = new Set();
  const admitted = new Set();
  const calls = [];
  const metrics = { connections: 0, peakSockets: 0, peakSessions: 0, active: 0, maxActive: 0, errors: 0 };
  const state = { override: options.override, chainId: CHAIN_ID, owners: OWNERS.slice(0, options.producers ?? 4) };
  const blockId = `0x1220${'ac'.repeat(32)}`;
  const server = http.createServer(async (request, response) => {
    let body = '';
    for await (const chunk of request) body += chunk;
    const rpc = JSON.parse(body);
    calls.push(rpc);
    metrics.active++;
    metrics.maxActive = Math.max(metrics.maxActive, metrics.active);
    response.once('close', () => metrics.active--);
    response.setHeader('Content-Type', 'application/json');
    const fail = (status, message, code = -32001) => {
      metrics.errors++;
      response.statusCode = status;
      response.end(JSON.stringify({ jsonrpc: '2.0', id: rpc.id, error: { code, message } }));
    };
    if (!admitted.has(request.socket)) {
      response.setHeader('Connection', 'close');
      return fail(503, 'JSON-RPC session limit reached');
    }
    await sleep(options.delayMs ?? 5);
    try {
      const override = await state.override?.(rpc, calls);
      if (override?.hang) return;
      if (override?.error) return fail(override.status ?? 200, override.error, override.code ?? -1);
      let result = override?.result;
      if (result === undefined) {
        if (rpc.method === 'chain.get_chain_id') result = { chain_id: state.chainId };
        else if (rpc.method === 'chain.get_head_info') result = { head_topology: { id: blockId, height: '120' } };
        else if (rpc.method === 'block_store.get_blocks_by_height') {
          result = { block_items: Array.from({ length: rpc.params.num_blocks }, (_, index) => ({
            block_height: String(rpc.params.ancestor_start_height + index),
            block: { header: { signer: state.owners[index % state.owners.length], timestamp: String(Date.now()) } },
          })) };
        } else if (rpc.method === 'chain.read_contract') {
          const { contract_id: id, entry_point: entry } = rpc.params;
          if (id === KOIN || id === VHP) {
            const method = entry === tokenAbi.methods.balance_of.entry_point ? 'balance_of' : 'total_supply';
            result = { result: utils.encodeBase64url(await token.serialize({ value: method === 'balance_of' ? (id === KOIN ? '12300000000' : '45600000000') : '100000000000000' }, tokenAbi.methods[method].return)) };
          } else result = { result: utils.encodeBase64url(await fogata.serialize({ name: 'Synthetic Pool' }, fogataAbi.methods.get_pool_params.return)) };
        } else throw new Error('Unexpected RPC method');
      }
      response.end(JSON.stringify({ jsonrpc: '2.0', id: rpc.id, result }));
    } catch { fail(200, 'Synthetic contract error', -1); }
  });
  server.keepAliveTimeout = 10000;
  server.on('connection', socket => {
    metrics.connections++;
    sockets.add(socket);
    if (admitted.size < (options.maxSessions ?? 4)) admitted.add(socket);
    metrics.peakSockets = Math.max(metrics.peakSockets, sockets.size);
    metrics.peakSessions = Math.max(metrics.peakSessions, admitted.size);
    socket.once('close', () => { sockets.delete(socket); admitted.delete(socket); });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${server.address().port}/`, calls, metrics, state,
    openSockets: () => sockets.size,
    close: async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); } };
}

module.exports = { createDashboardRpc, CHAIN_ID, KOIN, VHP, OWNERS, sleep };
