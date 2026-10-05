const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { Signer, Contract, Transaction, utils } = require('koilib');
const P = require('../dist/vortex-protocol');
const V = require('../dist/vortex');
const admins = [1, 2, 3].map(n => Signer.fromSeed('kcli-disposable-test-admin-' + n));
const validators = [1, 2, 3].map(n => Signer.fromSeed('kcli-disposable-test-validator-' + n));
const payer = Signer.fromSeed('kcli-disposable-test-payer');
const bridge = Signer.fromSeed('kcli-disposable-test-contract');
const code = Buffer.from('synthetic-test-code-not-wasm');
const chainId = utils.encodeBase64url(Buffer.from('1220' + P.sha('kcli-synthetic-chain'), 'hex'));
function fixture(dir) {
  const types = structuredClone(P.BRIDGE_TYPES);
  const methods = Object.fromEntries(Object.entries(P.METHODS).map(([n, r]) => [n, { argument: 'bridge.' + n + '_arguments', return: 'bridge.' + r, entry_point: P.entryPoint(n), read_only: n.startsWith('get_') || n === 'is_paused' }]));
  const abiText = JSON.stringify({ methods, types: { nested: { bridge: { nested: types } } } });
  const manifest = { schema: 1, source: { repository: P.VORTEX_REPOSITORY, commit: P.VORTEX_PIN, variant: 'pinned-migration', adapterSha256: null }, network: { name: 'local', chainId }, contract: { address: bridge.address, codeSha256: P.sha(code), abiSha256: P.sha(abiText) }, policy: { reviewed: true, admins: admins.map(s => s.address), adminThreshold: 2, recoveryThreshold: 3, validators: validators.map(s => s.address), payer: payer.address, delayMs: '172800000', actionWindowMs: '86400000' } };
  const manifestFile = path.join(dir, 'manifest.json'), abiFile = path.join(dir, 'abi.json');
  fs.writeFileSync(manifestFile, JSON.stringify(manifest), { mode: 0o600 }); fs.writeFileSync(abiFile, abiText, { mode: 0o600 });
  const ctx = V.loadVortex(manifestFile, abiFile);
  const config = { migrated: true, migrationFinalized: true, ethBridge: '0x' + '01'.repeat(20), ethChain: 2, adminThreshold: 2, depositNonce: '0', pauseNonce: '0', adminCount: 3, setupFrozenAt: '1', epoch: '1', proposalNonce: '0', recoveryThreshold: 3, pausedAt: '1' };
  const snapshot = { config, paused: false, admins: manifest.policy.admins, validators: manifest.policy.validators, head: { id: '0x1220' + '03'.repeat(32), height: '100', time: '400000000', lib: '90' }, proposal: null };
  async function pkg(action = 'pause', args = {}, proposed = false) {
    const op = await V.encodeAction(ctx, action, args, proposed); const tx = await Transaction.prepareTransaction({ header: { chain_id: chainId, rc_limit: '200000000', nonce: 'KAE=', payer: payer.address }, operations: [op], signatures: [] });
    const snap = structuredClone(snapshot);
    if (action === 'unpause') snap.paused = true;
    let hash = null; if (proposed) {
      const inner = await V.encodeAction(ctx, action, args); hash = P.actionHash(inner.call_contract.entry_point, inner.call_contract.args);
    } else if (['unpause', 'recover_validators'].includes(action)) hash = P.actionHash(op.call_contract.entry_point, op.call_contract.args);
    if (hash) snap.proposal = { hash, eta: proposed ? '0' : '350000000', nonce: proposed ? '0' : '1', epoch: proposed ? '0' : '1', kind: action === 'recover_validators' && !proposed ? 1 : 0 };
    if (action === 'cancel') snap.proposal = { hash: args.actionHash, eta: '200000000', nonce: '1', epoch: '1', kind: 0 };
    return { schema: 1, manifestSha256: ctx.manifestSha256, abiSha256: ctx.abiSha256, transaction: tx, snapshot: snap };
  }
  return { ctx, manifest, manifestFile, abiFile, abiText, snapshot, pkg };
}
async function rpcFixture(f, overrides = {}) {
  const state = { config: structuredClone(f.snapshot.config), paused: false, proposal: { eta: '0', nonce: '0', epoch: '0', kind: 0 }, nonce: 'KAA=', mana: '1000000000', sends: 0, tx: null, irreversible: false, ...overrides };
  const contract = new Contract({ id: bridge.address, abi: f.ctx.abi });
  async function answer(method, params) {
    if (state.failure === method) throw Error('synthetic sensitive response must be withheld');
    if (method === 'chain.get_chain_id') return { chain_id: state.chainId || chainId };
    if (method === 'contract_meta_store.get_contract_meta') return { meta: { abi: state.abiText || f.abiText } };
    if (method === 'chain.get_head_info') return { head_topology: { id: f.snapshot.head.id, height: '100' }, head_state_merkle_root: 'synthetic-stable-state', head_block_time: state.time || '400000000', last_irreversible_block: state.irreversible ? '100' : '90' };
    if (method === 'chain.get_account_nonce') return { nonce: state.nonce };
    if (method === 'chain.get_account_rc') return { rc: state.mana };
    if (method === 'chain.invoke_system_call') {
      const q = await P.kernel.deserialize(params.args, 'Query'); let object = { exists: false, value: '', key: '' };
      if (q.space.system && q.space.id === 2) object = { exists: true, value: utils.encodeBase64url(state.code || code), key: '' };
      if (q.space.system && q.space.id === 3) object = { exists: true, value: utils.encodeBase64url(await P.kernel.serialize({ hash: utils.encodeBase64url(Buffer.from('1220' + P.sha(code), 'hex')), call: true, transaction: true, upload: true }, 'Metadata')), key: '' };
      if (!q.space.system && [100, 201].includes(q.space.id)) {
        if (params.caller_data?.caller !== bridge.address || params.caller_data?.caller_privilege !== 'user_mode') throw Error('wrong storage caller context');
        const list = (q.space.id === 100 ? state.validators || validators.map(s => s.address) : state.admins || admins.map(s => s.address)).map(a => Buffer.from(utils.decodeBase58(a))).sort(Buffer.compare);
        const match = list.find(b => Buffer.compare(b, Buffer.from(utils.decodeBase64url(q.key))) > 0);
        if (match) object = { exists: true, value: '', key: utils.encodeBase64url(match) };
      }
      if (!object.exists) return {}; // Native JSON-RPC omits the default empty byte result.
      return { value: utils.encodeBase64url(await P.kernel.serialize({ value: object }, 'Result')) };
    }
    if (method === 'chain.read_contract') {
      const d = await contract.decodeOperation({ call_contract: params });
      const results = { get_config: state.config, is_paused: { value: state.paused }, get_proposal: state.proposal };
      const type = f.ctx.abi.methods[d.name].return;
      return { result: utils.encodeBase64url(await contract.serializer.serialize(results[d.name], type)) };
    }
    if (method === 'chain.submit_transaction') {
      state.sends++; state.tx = params.transaction;
      if (state.unknown) throw Error('unknown result');
      if (!state.reverted) { state.paused = true; state.config.pauseNonce = '1'; }
      return { receipt: { id: state.tx.id, reverted: !!state.reverted } };
    }
    if (method === 'transaction_store.get_transactions_by_id') return { transactions: state.tx ? [{ transaction: state.tx, containing_blocks: [f.snapshot.head.id] }] : [] };
    if (method === 'block_store.get_blocks_by_id' || method === 'block_store.get_blocks_by_height') {
      const included = structuredClone(state.included || state.tx);
      if (included?.operations[0].call_contract.args === '') delete included.operations[0].call_contract.args;
      const blockId = method === 'block_store.get_blocks_by_height' && state.fork ? '0x1220' + '04'.repeat(32) : f.snapshot.head.id;
      return { block_items: [{ block_id: blockId, block_height: '100', block: { transactions: included ? [included] : [] }, receipt: { transaction_receipts: state.tx && !state.missingReceipt ? [{ id: state.tx.id, reverted: !!state.reverted }] : [] } }] };
    }
    throw Error('unsupported fixture method');
  }
  const server = http.createServer(async (req, res) => {
    const buffers = []; for await (const b of req) buffers.push(b); const j = JSON.parse(Buffer.concat(buffers));
    try { res.end(JSON.stringify({ jsonrpc: '2.0', id: j.id, result: await answer(j.method, j.params) })); }
    catch { res.end(JSON.stringify({ jsonrpc: '2.0', id: j.id, error: { code: -1, message: 'synthetic sensitive response must be withheld' } })); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { state, provider: new V.VortexProvider('http://127.0.0.1:' + server.address().port), close: () => new Promise(resolve => server.close(resolve)) };
}
module.exports = { fixture, rpcFixture, admins, validators, payer, bridge, chainId, code };
