const http = require('node:http');
const { Serializer, Signer, utils } = require('koilib');
const tokenAbi = require('../src/abis/token.json');

const CHAIN_ID = 'EiBZK_GGVP0H_fXVAM3j6EAuz3-B-l3ejxRSewi7qIBfSA==';
const TESTNET_ID = 'EiAIKVvm6-V2qmsmUvPJy09vCCLbtn9lHFpwrJbcTIEWRQ==';
const FUND = '1A5BmMqV5jN5zBrdkhQumAfDZBzXLPBeN9';
const SIGNER = Signer.fromSeed('kcli synthetic voting fixture; never use for real funds');
const VOTER = SIGNER.getAddress();

// Synthetic wire interface, built independently from the documented fund protocol.
function makeAbi() {
  const field = (id, type, rule) => ({ id, type, ...(rule && { rule }),
    ...(type === 'uint64' && { options: { jstype: 'JS_STRING' } }),
    ...(type === 'bytes' && { options: { '(koinos.btype)': 'ADDRESS' } }),
  });
  const message = fields => ({ fields: Object.fromEntries(fields.map(([name, ...args]) => [name, field(...args)])) });
  const nested = {
    get_project_arguments: message([['project_id', 1, 'uint32']]),
    get_user_votes_arguments: message([['voter', 1, 'bytes']]),
    update_vote_arguments: message([['voter', 1, 'bytes'], ['project_id', 2, 'uint32'], ['weight', 3, 'uint32']]),
    update_vote_result: message([]),
    get_projects_arguments: message([['status', 1, 'project_status'], ['order_by', 2, 'order_projects_by'], ['start', 3, 'string'], ['limit', 4, 'int32'], ['descending', 5, 'bool']]),
    get_projects_result: message([['projects', 1, 'project', 'repeated'], ['start_next_page', 2, 'string']]),
    get_user_votes_result: message([['votes', 1, 'vote_info', 'repeated']]),
    vote_info: message([['project_id', 1, 'uint32'], ['weight', 2, 'uint32'], ['expiration', 3, 'uint64']]),
    project: message([['id', 1, 'uint32'], ['creator', 2, 'bytes'], ['beneficiary', 3, 'bytes'], ['title', 4, 'string'], ['description', 5, 'string'], ['monthly_payment', 6, 'uint64'], ['start_date', 7, 'uint64'], ['end_date', 8, 'uint64'], ['status', 9, 'project_status'], ['total_votes', 10, 'uint64'], ['votes', 11, 'uint64', 'repeated']]),
    global_vars: message([['fee_denominator', 1, 'uint64'], ['total_projects', 2, 'uint32'], ['total_upcoming_projects', 3, 'uint32'], ['total_active_projects', 4, 'uint32'], ['payment_times', 5, 'uint64', 'repeated'], ['remaining_balance', 6, 'uint64']]),
    project_status: { values: { upcoming: 0, active: 1, past: 2 } },
    order_projects_by: { values: { by_date: 0, by_votes: 1 } },
  };
  const method = (entry_point, argument, result, read_only = true) => ({ entry_point, argument, return: result, read_only });
  return {
    methods: {
      get_global_vars: method(776169940, '', 'fund.global_vars'),
      get_project: method(3495374342, 'fund.get_project_arguments', 'fund.project'),
      get_projects: method(1544343095, 'fund.get_projects_arguments', 'fund.get_projects_result'),
      get_user_votes: method(1727410647, 'fund.get_user_votes_arguments', 'fund.get_user_votes_result'),
      update_vote: method(3406555806, 'fund.update_vote_arguments', 'fund.update_vote_result', false),
    },
    koilib_types: { nested: { fund: { nested } } },
  };
}

function project(id, extra = {}) {
  return { id, creator: VOTER, beneficiary: VOTER, title: `Synthetic project ${id}`,
    description: 'Local test data', monthly_payment: '100000000', start_date: '1700000000000',
    end_date: '2000000000000', status: 1, total_votes: '2000000000', votes: ['2000000000'], ...extra };
}

async function createRpc(options = {}) {
  const abi = options.abi || makeAbi();
  const serializer = new Serializer(makeAbi().koilib_types);
  const tokenSerializer = new Serializer(tokenAbi.koilib_types);
  const calls = [];
  const state = { votes: options.votes || [], submitted: [], projects: options.projects || [project(1), project(2), project(3)] };
  const blockId = `0x1220${'ab'.repeat(32)}`;
  const server = http.createServer(async (request, response) => {
    try {
      let body = '';
      for await (const chunk of request) body += chunk;
      const rpc = JSON.parse(body);
      calls.push(rpc);
      let result;
      const { method, params } = rpc;
      if (options.failMethod === method) throw new Error('Synthetic RPC failure');
      if (method === 'chain.get_chain_id') {
        const index = calls.filter(call => call.method === method).length - 1;
        result = { chain_id: options.chainIds?.[index] || options.chainId || CHAIN_ID };
      }
      else if (method === 'contract_meta_store.get_contract_meta') result = options.noAbi ? {} : { meta: { abi: JSON.stringify(abi) } };
      else if (method === 'chain.get_account_rc') result = { rc: options.mana ?? '10000000000' };
      else if (method === 'chain.get_account_nonce') result = { nonce: 'KAA=' };
      else if (method === 'chain.read_contract') {
        if (params.contract_id !== FUND) {
          const balance = params.contract_id === '19GYjDBVXU7keLbYvMLazsGQn3GTWHjHkK' ? (options.koin ?? '10000000000') : (options.vhp ?? '10000000000');
          result = { result: utils.encodeBase64url(await tokenSerializer.serialize({ value: balance }, tokenAbi.methods.balance_of.return)) };
        } else {
          const entry = Object.entries(abi.methods).find(([, info]) => info.entry_point === params.entry_point);
          if (!entry) throw new Error('Unexpected fund entry point');
          const [name, info] = entry;
          const args = info.argument ? await serializer.deserialize(params.args, info.argument) : {};
          let data;
          if (name === 'get_global_vars') data = { fee_denominator: '10000', total_projects: state.projects.length, total_active_projects: state.projects.length,
            total_upcoming_projects: 0, payment_times: Array(6).fill('2000000000000'), remaining_balance: '123456789012345678' };
          else if (name === 'get_project') {
            data = state.projects.find(p => p.id === args.project_id);
            if (!data) throw new Error('project not found');
          } else if (name === 'get_user_votes') data = { votes: state.votes };
          else if (name === 'get_projects') {
            const initial = args.descending ? '999999999999999999999999999' : '0';
            const offset = args.start === initial ? 0 : (args.start.startsWith('page-') ? Number(args.start.slice(5)) : NaN);
            const items = Number.isNaN(offset) ? [] : state.projects.filter(p => p.status === (args.status || 0)).slice(offset, offset + args.limit);
            data = { projects: items, start_next_page: options.repeatCursor ? args.start : `page-${offset + items.length}` };
          } else throw new Error('Write method called as a read');
          result = { result: utils.encodeBase64url(await serializer.serialize(data, info.return)) };
        }
      } else if (method === 'chain.submit_transaction') {
        const tx = params.transaction;
        if (tx.header.chain_id !== (options.chainId || CHAIN_ID)) throw new Error('Wrong chain in transaction');
        const addresses = await Signer.recoverAddresses(tx);
        if (addresses.length !== 1 || addresses[0] !== VOTER) throw new Error('Invalid synthetic transaction signature');
        state.submitted.push(tx);
        const vote = await serializer.deserialize(tx.operations[0].call_contract.args, 'fund.update_vote_arguments');
        if (!options.noApply && !options.reverted) {
          state.votes = state.votes.filter(v => v.project_id !== vote.project_id);
          if (vote.weight) state.votes.push({ project_id: vote.project_id, weight: vote.weight, expiration: '2000000000000' });
        }
        result = { receipt: { id: tx.id, payer: tx.header.payer, reverted: !!options.reverted, logs: [], ...(options.rpcError && { rpc_error: 'unknown outcome' }) } };
      } else if (method === 'transaction_store.get_transactions_by_id') {
        result = { transactions: options.timeout ? [] : [{ containing_blocks: [blockId] }] };
      } else if (method === 'chain.get_head_info') result = { head_topology: { id: blockId, height: '123' }, head_block_time: '1800000000000' };
      else if (method === 'block_store.get_blocks_by_id' || method === 'block_store.get_blocks_by_height') {
        result = { block_items: [{ block_id: blockId, block_height: '123', receipt: { transaction_receipts: options.noReceipt ? [] : state.submitted.map(tx => ({ id: tx.id, reverted: !!options.includedReverted, logs: [] })) } }] };
      } else throw new Error(`Unexpected RPC method ${method}`);
      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify({ jsonrpc: '2.0', id: rpc.id, result }));
    } catch (error) {
      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code: -1, message: error.message } }));
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { calls, state, url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise(resolve => server.close(resolve)) };
}

module.exports = { CHAIN_ID, TESTNET_ID, FUND, SIGNER, VOTER, makeAbi, project, createRpc };
