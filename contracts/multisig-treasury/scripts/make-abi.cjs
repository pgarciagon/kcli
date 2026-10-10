// Renders the deployed ABI from protoc's FileDescriptorSet (--include_imports). No dependencies.
// usage: node make-abi.cjs <treasury.pb> <treasury.abi out>
'use strict';
const fs = require('fs');
const crypto = require('crypto');
const ep = name => parseInt(crypto.createHash('sha256').update(name).digest('hex').slice(0, 8), 16);
const address = { '(koinos.btype)': 'ADDRESS' };
const methods = {
  set_policy: { argument: 'treasury.set_policy_arguments', return: 'treasury.empty_object', description: 'Atomically replace the complete owner set and threshold; requires the current owner quorum', entry_point: ep('set_policy'), read_only: false },
  get_policy: { argument: 'treasury.get_policy_arguments', return: 'treasury.policy_object', description: 'Current owner policy', entry_point: ep('get_policy'), read_only: true },
  get_template: { argument: 'treasury.get_template_arguments', return: 'treasury.template_info', description: 'Contract template identity and immutable deployment bindings', entry_point: ep('get_template'), read_only: true },
};
const koilib_types = { nested: { treasury: { nested: {
  set_policy_arguments: { fields: { owners: { rule: 'repeated', type: 'bytes', id: 1, options: address }, threshold: { type: 'uint32', id: 2 } } },
  get_policy_arguments: { fields: {} },
  get_template_arguments: { fields: {} },
  empty_object: { fields: {} },
  policy_object: { fields: { owners: { rule: 'repeated', type: 'bytes', id: 1, options: address }, threshold: { type: 'uint32', id: 2 }, version: { type: 'uint64', id: 3, options: { jstype: 'JS_STRING' } } } },
  template_info: { fields: { name: { type: 'string', id: 1 }, version: { type: 'string', id: 2 }, chain_id: { type: 'bytes', id: 3 }, koin_contract: { type: 'bytes', id: 4, options: { '(koinos.btype)': 'CONTRACT_ID' } }, min_owners: { type: 'uint32', id: 5 }, max_owners: { type: 'uint32', id: 6 } } },
} } } };
const types = fs.readFileSync(process.argv[2]).toString('base64');
fs.writeFileSync(process.argv[3], JSON.stringify({ methods, types, koilib_types }, null, 2) + '\n');
