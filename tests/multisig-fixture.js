// Synthetic, disposable multisig fixtures and a local JSON-RPC simulator (no chain, no public network).
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { Signer, Contract, Serializer, utils } = require('koilib');
const VP = require('../dist/vortex-protocol');
const MP = require('../dist/multisig-protocol');
const M = require('../dist/multisig');

const bySeed = s => Signer.fromSeed('kcli-disposable-multisig-' + s);
const sortSigners = list => list.sort((a, b) => MP.compareAddresses(a.address, b.address));
const owners = sortSigners([1, 2, 3, 4, 5].map(n => bySeed('owner-' + n)));
const outsider = bySeed('outsider');
const treasury = bySeed('treasury');
const koin = bySeed('koin-contract').address;
const recipient = bySeed('recipient').address;
const code = Buffer.from('synthetic-treasury-code-not-wasm');
const chainId = utils.encodeBase64url(Buffer.from('1220' + VP.sha('kcli-synthetic-multisig-chain'), 'hex'));
const h = s => VP.sha(s);

function manifestFor(policy = { owners: owners.map(s => s.address), threshold: 3, version: '0' }) {
  return { schema: 1, kind: 'kcli-multisig-treasury', network: { name: 'local', chainId }, token: { symbol: 'KOIN', contract: koin, decimals: 8 },
    treasury: { address: treasury.address, template: MP.TEMPLATE_NAME, templateVersion: MP.TEMPLATE_VERSION, codeSha256: VP.sha(code), abiSha256: h('abi'), sourceSha256: h('source'), inputsSha256: h('inputs'),
      bootstrap: { transactionId: '0x1220' + h('bootstrap'), blockId: '0x1220' + h('block-50'), height: '50' } },
    policy };
}
function fixture(dir, manifest = manifestFor(), review, reviewKey) {
  const manifestFile = path.join(dir, 'treasury.json'); fs.writeFileSync(manifestFile, JSON.stringify(manifest, null, 2), { mode: 0o600 });
  const ctx = M.loadManifest(manifestFile, review, reviewKey);
  const snapshot = { head: { id: '0x1220' + '03'.repeat(32), height: '100', time: '400000000', lib: '90' }, nonce: '1', balance: '100000000000', mana: '100000000000', policyVersion: manifest.policy.version };
  async function pkg(kind = 'transfer', opts = {}) {
    const op = kind === 'transfer' ? await MP.encodeTransfer(treasury.address, manifest.token.contract, opts.to || recipient, opts.raw || 150000000n)
      : await MP.encodePolicy(treasury.address, opts.owners || owners.slice(0, 3).map(s => s.address).sort(MP.compareAddresses), opts.threshold || 2);
    const { Transaction } = require('koilib');
    const transaction = await Transaction.prepareTransaction({ header: { chain_id: manifest.network.chainId, rc_limit: '10000000', nonce: utils.encodeBase64url(Buffer.from([40, 2])), payer: treasury.address }, operations: [op], signatures: [] });
    return { schema: 1, kind: 'kcli-multisig-transaction', manifestSha256: ctx.manifestSha256, note: opts.note ?? null, transaction, snapshot: structuredClone(snapshot) };
  }
  return { ctx, manifest, manifestFile, snapshot, pkg };
}
async function signedBy(f, p, signers) { for (const s of signers) p = await M.appendSignature(f.ctx, p, s, p.transaction.id); return p; }

// ------------------------------------------------------------------------------------------ RPC simulator
async function rpcFixture(f, overrides = {}) {
  const chainId = f.manifest.network.chainId, koin = f.manifest.token.contract;
  const state = { nonce: 'KAE=', mana: '100000000000', balance: '100000000000', policy: { owners: f.manifest.policy.owners, threshold: f.manifest.policy.threshold, version: f.manifest.policy.version },
    allowances: [], storedPolicy: false, sends: 0, tx: null, irreversible: false, calls: [], ...overrides };
  const T = new Contract({ id: treasury.address, abi: MP.TREASURY_ABI }), K = new Contract({ id: koin, abi: MP.KOIN_ABI });
  const ser = new Serializer(MP.KOIN_ABI.koilib_types);
  const blockId = height => height === 100 ? f.snapshot.head.id : '0x1220' + VP.sha('synthetic-block-' + height);
  async function answer(method, params) {
    state.calls.push(method);
    if (state.beforeCall) await state.beforeCall(method, params, state);
    if (state.failure === method) throw Error('synthetic sensitive response must be withheld');
    if (method === 'chain.get_chain_id') return { chain_id: state.chainId || chainId };
    if (method === 'chain.get_head_info') {
      const height = state.height ?? 100; if (state.advancing) state.height = height + 1;
      return { head_topology: { id: blockId(height), height: String(height) }, head_state_merkle_root: state.root || 'synthetic-stable-state', head_block_time: state.time || '400000000', last_irreversible_block: state.lib || (state.irreversible ? '100' : '90') };
    }
    if (method === 'chain.get_account_nonce') return params.account === treasury.address ? { nonce: state.nonce } : {};
    if (method === 'chain.get_account_rc') return { rc: state.mana };
    if (method === 'chain.invoke_system_call') {
      const q = await VP.kernel.deserialize(params.args, 'Query'); let object = { exists: false, value: '', key: '' };
      const own = q.key === utils.encodeBase64url(utils.decodeBase58(treasury.address));
      if (q.space.system && q.space.id === 3 && q.key === utils.encodeBase64url(utils.decodeBase58(koin))) object = { exists: true, value: utils.encodeBase64url(await VP.kernel.serialize({ hash: utils.encodeBase64url(Buffer.from('1220' + VP.sha('synthetic-koin-code'), 'hex')), call: true, transaction: true, upload: true, system: true }, 'Metadata')), key: '' };
      if (q.space.system && q.space.id === 2 && own && !state.noCode) object = { exists: true, value: utils.encodeBase64url(state.code || code), key: '' };
      if (q.space.system && q.space.id === 3 && own && !state.noCode) object = { exists: true, value: utils.encodeBase64url(await VP.kernel.serialize({ hash: utils.encodeBase64url(Buffer.from('1220' + VP.sha(state.code || code), 'hex')), call: true, transaction: true, upload: true, ...(state.authority || {}) }, 'Metadata')), key: '' };
      if (!q.space.system && state.storedPolicy && params.name === 'get_object') object = { exists: true, value: 'AA==', key: '' };
      if (!object.exists) return {};
      return { value: utils.encodeBase64url(await VP.kernel.serialize({ value: object }, 'Result')) };
    }
    if (method === 'chain.read_contract') {
      if (params.contract_id === require('../dist/multisig-network').PUBLIC_FUND.mainnet) return {};
      if (params.contract_id === treasury.address) {
        const d = await T.decodeOperation({ call_contract: { contract_id: params.contract_id, entry_point: params.entry_point, args: params.args || '' } });
        const results = { get_policy: state.policy, get_template: { name: MP.TEMPLATE_NAME, version: MP.TEMPLATE_VERSION, chain_id: chainId, koin_contract: koin, min_owners: 3, max_owners: 15 } };
        return { result: utils.encodeBase64url(await T.serializer.serialize(results[d.name], MP.TREASURY_ABI.methods[d.name].return)) };
      }
      const d = await K.decodeOperation({ call_contract: { contract_id: params.contract_id, entry_point: params.entry_point, args: params.args || '' } });
      const results = { balance_of: { value: state.balance }, get_allowances: { owner: treasury.address, allowances: state.allowances } };
      return { result: utils.encodeBase64url(await K.serializer.serialize(results[d.name], MP.KOIN_ABI.methods[d.name].return)) };
    }
    if (method === 'chain.submit_transaction') {
      state.sends++;
      if (state.unknown === 'lost') throw Error('unknown result');
      state.tx = params.transaction;
      if (state.unknown === 'accepted') throw Error('unknown result');
      return { receipt: { id: state.tx.id, reverted: !!state.reverted } };
    }
    if (method === 'transaction_store.get_transactions_by_id') return { transactions: state.tx ? [{ transaction: state.tx, containing_blocks: [f.snapshot.head.id] }] : [] };
    if (method === 'block_store.get_blocks_by_id' || method === 'block_store.get_blocks_by_height') {
      const included = structuredClone(state.included || state.tx);
      const height = method === 'block_store.get_blocks_by_height' ? Number(params.ancestor_start_height) : 100;
      const id = state.fork ? '0x1220' + '04'.repeat(32) : blockId(height);
      let events = [];
      if (state.tx && !state.reverted && state.tx.operations[0].call_contract) {
        const r = await MP.reviewOperation(state.tx.operations[0].call_contract, treasury.address, koin);
        if (r.kind === 'transfer') events = [{ name: 'token.transfer_event', source: koin, data: utils.encodeBase64url(await ser.serialize({ from: treasury.address, to: state.eventTo || r.to, value: r.raw }, 'koin.transfer_event')), impacted: [r.to, treasury.address] }];
      }
      const anchor = height === 100 ? (state.anchor || {}) : {};
      return { block_items: [{ block_id: id, block_height: String(height), block: { id: anchor.blockId || id, header: { height: anchor.headerHeight || String(height), previous: blockId(height - 1) }, transactions: included && height === 100 ? [included] : [] },
        receipt: { id: anchor.receiptId || id, height: anchor.receiptHeight || String(height), state_delta_entries: height > 100 ? (state.deltas || []) : [], transaction_receipts: state.tx && height === 100 ? [{ id: state.tx.id, reverted: !!state.reverted, events }] : [] } }] };
    }
    throw Error('unsupported fixture method');
  }
  const server = http.createServer(async (req, res) => {
    const buffers = []; for await (const b of req) buffers.push(b); const j = JSON.parse(Buffer.concat(buffers));
    if (state.httpStatus) { res.writeHead(state.httpStatus); res.end('no'); return; }
    try { res.end(JSON.stringify({ jsonrpc: '2.0', id: j.id, result: await answer(j.method, j.params) })); }
    catch { res.end(JSON.stringify({ jsonrpc: '2.0', id: j.id, error: { code: -1, message: 'synthetic sensitive response must be withheld' } })); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const url = 'http://127.0.0.1:' + server.address().port;
  const { MultisigProvider } = require('../dist/multisig-network');
  return { state, url, server, answer, provider: (deadlineMs = 60000) => new MultisigProvider(url, 'local', Date.now() + deadlineMs), close: () => new Promise(resolve => server.close(resolve)) };
}
module.exports = { fixture, manifestFor, rpcFixture, signedBy, owners, outsider, treasury, koin, recipient, chainId, code, bySeed };
