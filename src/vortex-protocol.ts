import { createHash } from 'crypto';
import { Abi, Contract, Serializer, utils } from 'koilib';
import { canonical, objectKeys, RefusalError, requireValue } from './secure-files';

export const VORTEX_PIN = '42b0ab20653047ec0275c3130accf9210ce4b822';
export const VORTEX_REPOSITORY = 'https://github.com/VortexBridge/vortex-bridge-v2';
export const DELAY_MS = 172800000n;
export const WINDOW_MS = 86400000n;
export const sha = (data: string | Uint8Array): string => createHash('sha256').update(data).digest('hex');
export const digest = (data: Uint8Array): Buffer => createHash('sha256').update(data).digest();
export function address(v: any): string { requireValue(typeof v === 'string' && utils.isChecksumAddress(v), 'Invalid public address.'); return v; }
export function uint(v: any, positive = false): bigint {
  requireValue(typeof v === 'string' && /^(0|[1-9]\d{0,19})$/.test(v), 'Expected a canonical uint64 string.');
  const n = BigInt(v); requireValue(n <= 0xffffffffffffffffn && (!positive || n > 0n), 'uint64 out of range.'); return n;
}
export function b64(v: any, length?: number, maxChars = 16384): Buffer {
  requireValue(typeof v === 'string' && /^(?:[A-Za-z0-9_-]*)(?:={0,2})$/.test(v) && v.length <= maxChars, 'Invalid base64url.');
  const bytes = Buffer.from(utils.decodeBase64url(v));
  requireValue(utils.encodeBase64url(bytes) === v && (length === undefined || bytes.length === length), 'Noncanonical base64url or wrong length.'); return bytes;
}
export function varint(v: bigint): Buffer {
  const bytes = []; do { const b = Number(v & 127n); v >>= 7n; bytes.push(b | (v ? 128 : 0)); } while (v); return Buffer.from(bytes);
}
export function bytesField(id: number, bytes: Uint8Array): Buffer {
  return bytes.length ? Buffer.concat([varint(BigInt(id * 8 + 2)), varint(BigInt(bytes.length)), bytes]) : Buffer.alloc(0);
}
export function uintField(id: number, value: bigint): Buffer { return value ? Buffer.concat([varint(BigInt(id * 8)), varint(value)]) : Buffer.alloc(0); }
export function nonceValue(nonce: string): bigint {
  const bytes = b64(nonce); requireValue(bytes.length >= 2 && bytes[0] === 40, 'Unsupported payer nonce encoding.');
  let value = 0n; let shift = 0n;
  for (let i = 1; i < bytes.length; i++) {
    requireValue(shift < 70n, 'Nonce out of range.'); value |= BigInt(bytes[i] & 127) << shift; shift += 7n;
    if (bytes[i] < 128) { requireValue(i === bytes.length - 1 && value <= 0xffffffffffffffffn && Buffer.concat([Buffer.from([40]), varint(value)]).equals(bytes), 'Invalid nonce encoding.'); return value; }
  }
  throw new RefusalError('Invalid nonce encoding.');
}

// Independent protocol encoder, restricted to one call; never prepares or mutates a signed transaction.
export function transactionId(tx: any): string {
  objectKeys(tx, ['id', 'header', 'operations', 'signatures']);
  const h = tx.header; objectKeys(h, ['chain_id', 'rc_limit', 'nonce', 'operation_merkle_root', 'payer']);
  requireValue(Array.isArray(tx.operations) && tx.operations.length === 1 && Array.isArray(tx.signatures), 'Exactly one reviewed operation is supported.');
  objectKeys(tx.operations[0], ['call_contract']); const c = tx.operations[0].call_contract;
  objectKeys(c, ['contract_id', 'entry_point', 'args']); address(c.contract_id); address(h.payer);
  requireValue(Number.isInteger(c.entry_point) && c.entry_point > 0 && c.entry_point <= 0xffffffff, 'Invalid entry point.');
  requireValue(nonceValue(h.nonce) > 0n, 'Transaction payer nonce must be positive.');
  const call = Buffer.concat([bytesField(1, utils.decodeBase58(c.contract_id)), uintField(2, BigInt(c.entry_point)), bytesField(3, b64(c.args))]);
  const root = Buffer.concat([Buffer.from([18, 32]), digest(bytesField(2, call))]);
  requireValue(root.equals(b64(h.operation_merkle_root, 34)), 'Operation Merkle root changed.');
  const chain = b64(h.chain_id, 34); requireValue(chain[0] === 18 && chain[1] === 32, 'Invalid chain identity.');
  const header = Buffer.concat([bytesField(1, chain), uintField(2, uint(h.rc_limit, true)), bytesField(3, b64(h.nonce)), bytesField(4, root), bytesField(5, utils.decodeBase58(h.payer))]);
  return '0x1220' + sha(header);
}

const f = (type: string, id: number, kind?: string, repeated = false): any => ({ type, id, ...(repeated && { rule: 'repeated' }), ...(kind && { options: { '(koinos.btype)': kind } }), ...(type === 'uint64' && { options: { jstype: 'JS_STRING' } }) });
export const BRIDGE_TYPES: Record<string, any> = {
  empty_object: { fields: {} }, boole: { fields: { value: f('bool', 1) } },
  pause_arguments: { fields: { expiry: f('uint64', 1), signatures: f('bytes', 2, undefined, true) } },
  unpause_arguments: { fields: {} },
  recover_validators_arguments: { fields: { validators: f('bytes', 1, 'ADDRESS', true) } },
  propose_arguments: { fields: { entryPoint: f('uint32', 1), args: f('bytes', 2, 'HEX') } },
  cancel_arguments: { fields: { actionHash: f('bytes', 1, 'HEX'), expiry: f('uint64', 2), signatures: f('bytes', 3, undefined, true) } },
  get_config_arguments: { fields: {} }, is_paused_arguments: { fields: {} },
  get_proposal_arguments: { fields: { actionHash: f('bytes', 1, 'HEX') } },
  config_v2: { fields: { migrated: f('bool', 1), migrationFinalized: f('bool', 2), ethBridge: f('bytes', 3, 'HEX'), ethChain: f('uint32', 4), adminThreshold: f('uint32', 5), depositNonce: f('uint64', 6), pauseNonce: f('uint64', 7), adminCount: f('uint32', 9), setupFrozenAt: f('uint64', 10), epoch: f('uint64', 11), proposalNonce: f('uint64', 12), recoveryThreshold: f('uint32', 13), pausedAt: f('uint64', 14) } },
  proposal_v2: { fields: { eta: f('uint64', 1), nonce: f('uint64', 2), epoch: f('uint64', 3), kind: f('uint32', 4) } },
};
export const METHODS: Record<string, string> = { pause: 'empty_object', unpause: 'empty_object', recover_validators: 'empty_object', propose: 'empty_object', cancel: 'empty_object', get_config: 'config_v2', is_paused: 'boole', get_proposal: 'proposal_v2' };
export const entryPoint = (name: string): number => parseInt(sha(name).slice(0, 8), 16);
export function reviewedAbi(input: any, variant: string): Abi {
  requireValue(input && input.methods, 'Missing reviewed ABI.');
  const descriptor = input.koilib_types || input.types;
  // The pinned build supplies a FileDescriptorSet, whose source field names use snake case.
  // Convert it only for schema comparison; transaction encoding uses the fixed schema below.
  let schema = descriptor;
  if (typeof descriptor === 'string') {
    requireValue(descriptor.length <= 262144 && /^[A-Za-z0-9+/]*={0,2}$/.test(descriptor), 'Invalid ABI descriptor.');
    try { schema = new Serializer(descriptor).root.toJSON(); } catch { throw new RefusalError('Invalid ABI descriptor.'); }
  }
  const nested = schema?.nested?.bridge?.nested;
  requireValue(nested, 'Missing bridge wire schema.');
  const types = structuredClone(BRIDGE_TYPES);
  if (variant === 'fresh-initializer') types.config_v2.fields.freshDeployment = f('bool', 15);
  for (const [name, expected] of Object.entries(types)) {
    const fields = nested[name]?.fields; requireValue(fields && Object.keys(fields).length === Object.keys(expected.fields).length, 'Unreviewed ABI wire fields.');
    for (const [key, spec] of Object.entries<any>(expected.fields)) {
      const wireName = typeof descriptor === 'string' ? key.replace(/[A-Z]/g, c => '_' + c.toLowerCase()) : key;
      const actual = fields[wireName]; requireValue(actual && actual.id === spec.id && actual.type === spec.type && actual.rule === spec.rule && canonical(actual.options || {}) === canonical(spec.options || {}), 'Unreviewed ABI wire field or annotation.');
    }
  }
  const methods: any = {};
  for (const [name, output] of Object.entries(METHODS)) {
    const m = input.methods[name]; const ep = m?.entry_point ?? m?.entryPoint ?? Number(m?.['entry-point']);
    const ro = m?.read_only ?? m?.readOnly ?? m?.['read-only'];
    requireValue(ep === entryPoint(name) && ro === (name.startsWith('get_') || name === 'is_paused'), 'Unreviewed ABI entry point or authority.');
    requireValue((m.argument ?? m.input) === `bridge.${name}_arguments` && (m.return ?? m.output) === `bridge.${output}`, 'Unreviewed ABI method types.');
    methods[name] = { entry_point: entryPoint(name), read_only: name.startsWith('get_') || name === 'is_paused', argument: `bridge.${name}_arguments`, return: `bridge.${output}` };
  }
  return { methods, koilib_types: { nested: { bridge: { nested: types } } } };
}
export function actionHash(entry: number, args: string): string {
  const ep = Buffer.alloc(4); ep.writeUInt32BE(entry);
  return '0x1220' + sha(Buffer.concat([Buffer.from('vortex-bridge-v2/action'), ep, b64(args)]));
}

export async function decodeExact(contract: Contract, call: any): Promise<{ name: string; args: any }> {
  const decoded = await contract.decodeOperation({ call_contract: call });
  // The SDK renders empty HEX bytes as "0x", but refuses that same value when
  // re-encoding. Only propose.args may legitimately be empty in this adapter.
  if (decoded.name === 'propose' && decoded.args?.args === '0x') decoded.args.args = '';
  const reencoded = await contract.encodeOperation({ name: decoded.name, args: decoded.args });
  requireValue(canonical(reencoded.call_contract) === canonical(call), 'Unknown, noncanonical or unexplained action bytes.');
  return { name: decoded.name, args: decoded.args || {} };
}

// Kernel object access uses a fixed schema, never an ABI supplied by the RPC or review package.
export const kernel = new Serializer({ nested: {
  Space: { fields: { system: f('bool', 1), zone: f('bytes', 2), id: f('uint32', 3) } },
  Query: { fields: { space: f('Space', 1), key: f('bytes', 2) } },
  Object: { fields: { exists: f('bool', 1), value: f('bytes', 2), key: f('bytes', 3) } },
  Result: { fields: { value: f('Object', 1) } },
  Metadata: { fields: { hash: f('bytes', 1), system: f('bool', 2), call: f('bool', 3), transaction: f('bool', 4), upload: f('bool', 5) } },
} });
