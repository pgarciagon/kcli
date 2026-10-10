import { Abi, Contract, utils } from 'koilib';
import { canonical, objectKeys, RefusalError, requireValue } from './secure-files';
import { address, b64, bytesField, decodeExact, digest, nonceValue, sha, uint, uintField } from './vortex-protocol';

// Contract template 1.0.0 (contracts/multisig-treasury). Client-side rules mirror the contract exactly; the
// contract remains the enforcement point.
export const TEMPLATE_NAME = 'koinos-multisig-treasury';
export const TEMPLATE_VERSION = '1.0.0';
export const MIN_OWNERS = 3;
export const MAX_OWNERS = 15;
export const KOIN_DECIMALS = 8;
export const entryPoint = (name: string): number => parseInt(sha(name).slice(0, 8), 16);
export const TRANSFER_ENTRY_POINT = 0x27f576ca;
export const SET_POLICY_ENTRY_POINT = 0x1429285f;

const f = (type: string, id: number, kind?: string, repeated = false): any => ({ type, id, ...(repeated && { rule: 'repeated' }), ...(kind && { options: { '(koinos.btype)': kind } }), ...(type === 'uint64' && { options: { jstype: 'JS_STRING' } }) });
const method = (pkg: string, name: string, result: string, readOnly: boolean) => ({ entry_point: entryPoint(name), argument: `${pkg}.${name}_arguments`, return: `${pkg}.${result}`, read_only: readOnly });

// Fixed wire schemas: never taken from an RPC, a package or on-chain ABI metadata.
export const TREASURY_ABI: Abi = {
  methods: { set_policy: method('treasury', 'set_policy', 'empty_object', false), get_policy: method('treasury', 'get_policy', 'policy_object', true), get_template: method('treasury', 'get_template', 'template_info', true) },
  koilib_types: { nested: { treasury: { nested: {
    set_policy_arguments: { fields: { owners: f('bytes', 1, 'ADDRESS', true), threshold: f('uint32', 2) } },
    get_policy_arguments: { fields: {} }, get_template_arguments: { fields: {} }, empty_object: { fields: {} },
    policy_object: { fields: { owners: f('bytes', 1, 'ADDRESS', true), threshold: f('uint32', 2), version: f('uint64', 3) } },
    template_info: { fields: { name: f('string', 1), version: f('string', 2), chain_id: f('bytes', 3), koin_contract: f('bytes', 4, 'CONTRACT_ID'), min_owners: f('uint32', 5), max_owners: f('uint32', 6) } },
  } } } },
};
export const KOIN_ABI: Abi = {
  methods: { transfer: method('koin', 'transfer', 'empty_object', false), balance_of: { ...method('koin', 'balance_of', 'uint64', true) }, get_allowances: method('koin', 'get_allowances', 'get_allowances_result', true) },
  koilib_types: { nested: { koin: { nested: {
    transfer_arguments: { fields: { from: f('bytes', 1, 'ADDRESS'), to: f('bytes', 2, 'ADDRESS'), value: f('uint64', 3), memo: f('string', 4) } },
    empty_object: { fields: {} }, balance_of_arguments: { fields: { owner: f('bytes', 1, 'ADDRESS') } }, uint64: { fields: { value: f('uint64', 1) } },
    get_allowances_arguments: { fields: { owner: f('bytes', 1, 'ADDRESS'), start: f('bytes', 2, 'ADDRESS'), limit: f('int32', 3), descending: f('bool', 4) } },
    spender_value: { fields: { spender: f('bytes', 1, 'ADDRESS'), value: f('uint64', 2) } },
    get_allowances_result: { fields: { owner: f('bytes', 1, 'ADDRESS'), allowances: f('spender_value', 2, undefined, true) } },
    transfer_event: { fields: { from: f('bytes', 1, 'ADDRESS'), to: f('bytes', 2, 'ADDRESS'), value: f('uint64', 3), memo: f('string', 4) } },
  } } } },
};

const addressBytes = (a: string): Buffer => Buffer.from(utils.decodeBase58(address(a)));
export const compareAddresses = (a: string, b: string): number => Buffer.compare(addressBytes(a), addressBytes(b));

/// Exact decimal KOIN -> raw satoshis. No floating point, no exponent forms, at most 8 decimals.
export function parseAmount(text: string): bigint {
  requireValue(typeof text === 'string' && /^(0|[1-9]\d{0,11})(\.\d{1,8})?$/.test(text), 'Amount must be a plain decimal KOIN amount with at most 8 decimals.');
  const [whole, fraction = ''] = text.split('.');
  const raw = BigInt(whole) * 10n ** BigInt(KOIN_DECIMALS) + BigInt(fraction.padEnd(KOIN_DECIMALS, '0'));
  requireValue(raw > 0n && raw <= 0xffffffffffffffffn, 'Amount must be positive and within uint64.');
  return raw;
}
export function formatAmount(raw: bigint): string {
  const s = raw.toString().padStart(KOIN_DECIMALS + 1, '0');
  const whole = s.slice(0, -KOIN_DECIMALS), fraction = s.slice(-KOIN_DECIMALS).replace(/0+$/, '');
  return fraction ? `${whole}.${fraction}` : whole;
}

/// The contract's policy rules: 3-15 distinct valid owners in ascending byte order, none the treasury;
/// threshold >= 2, greater than half the owners and below the owner count.
export function validatePolicy(owners: any, threshold: any, treasury: string): void {
  requireValue(Array.isArray(owners) && owners.length >= MIN_OWNERS && owners.length <= MAX_OWNERS, `A policy needs ${MIN_OWNERS}-${MAX_OWNERS} owners.`);
  owners.forEach(address);
  for (let i = 1; i < owners.length; i++) requireValue(compareAddresses(owners[i - 1], owners[i]) < 0, 'Owners must be distinct and in ascending byte order.');
  requireValue(!owners.includes(treasury), 'The treasury cannot be its own owner.');
  const n = owners.length;
  requireValue(Number.isInteger(threshold) && threshold >= 2 && threshold > Math.floor(n / 2) && threshold < n, 'Threshold must be a majority of at least 2 and below the owner count.');
}
/// Canonical order for a user-supplied owner list (duplicates refuse, never silently merged).
export function canonicalOwners(list: any): string[] {
  requireValue(Array.isArray(list) && list.length <= MAX_OWNERS, 'Invalid owner list.'); list.forEach(address);
  requireValue(new Set(list).size === list.length, 'Duplicate owner identities.');
  return [...list].sort(compareAddresses);
}

/// Independent ID of the single-upload bootstrap transaction (never prepared or mutated by the SDK).
export function deployTransactionId(tx: any): string {
  objectKeys(tx, ['id', 'header', 'operations', 'signatures']);
  const h = tx.header; objectKeys(h, ['chain_id', 'rc_limit', 'nonce', 'operation_merkle_root', 'payer']);
  requireValue(Array.isArray(tx.operations) && tx.operations.length === 1 && Array.isArray(tx.signatures), 'The bootstrap is exactly one upload operation.');
  objectKeys(tx.operations[0], ['upload_contract']); const u = tx.operations[0].upload_contract;
  objectKeys(u, ['contract_id', 'bytecode', 'abi', 'authorizes_call_contract', 'authorizes_transaction_application', 'authorizes_upload_contract']);
  requireValue(u.authorizes_call_contract === true && u.authorizes_transaction_application === true && u.authorizes_upload_contract === true, 'All three authority overrides must be set at upload.');
  requireValue(typeof u.abi === 'string' && u.abi.length <= 65536, 'Invalid upload ABI.');
  address(u.contract_id); address(h.payer);
  const upload = Buffer.concat([bytesField(1, utils.decodeBase58(u.contract_id)), bytesField(2, b64(u.bytecode, undefined, 400000)), bytesField(3, Buffer.from(u.abi, 'utf8')), uintField(4, 1n), uintField(5, 1n), uintField(6, 1n)]);
  const root = Buffer.concat([Buffer.from([18, 32]), digest(bytesField(1, upload))]);
  requireValue(root.equals(b64(h.operation_merkle_root, 34)), 'Operation Merkle root changed.');
  const chain = b64(h.chain_id, 34); requireValue(chain[0] === 18 && chain[1] === 32, 'Invalid chain identity.');
  requireValue(nonceValue(h.nonce) > 0n, 'Transaction nonce must be positive.');
  const header = Buffer.concat([bytesField(1, chain), uintField(2, uint(h.rc_limit, true)), bytesField(3, b64(h.nonce)), bytesField(4, root), bytesField(5, utils.decodeBase58(h.payer))]);
  return '0x1220' + sha(header);
}

export interface TreasuryAction { kind: 'transfer' | 'policy'; to?: string; amount?: string; raw?: string; owners?: string[]; threshold?: number; }
/// Decode the single operation exactly (re-encoding must reproduce the signed bytes) and apply the contract's
/// envelope rules. Anything else -- allowance, burn, memo, other contracts -- is refused.
export async function reviewOperation(call: any, treasury: string, koin: string): Promise<TreasuryAction> {
  objectKeys(call, ['contract_id', 'entry_point', 'args']); address(call.contract_id);
  if (call.contract_id === koin) {
    requireValue(call.entry_point === TRANSFER_ENTRY_POINT, 'Only a KOIN transfer is supported.');
    const { name, args } = await decodeExact(new Contract({ id: koin, abi: KOIN_ABI }), call);
    requireValue(name === 'transfer' && args.from === treasury && !args.memo, 'Transfer must come from the treasury, without memo.');
    address(args.to); requireValue(args.to !== treasury, 'The treasury cannot pay itself.');
    const raw = uint(args.value, true);
    return { kind: 'transfer', to: args.to, raw: raw.toString(), amount: formatAmount(raw) };
  }
  requireValue(call.contract_id === treasury && call.entry_point === SET_POLICY_ENTRY_POINT, 'Unsupported operation. No arbitrary-call bypass is provided.');
  const { name, args } = await decodeExact(new Contract({ id: treasury, abi: TREASURY_ABI }), call);
  requireValue(name === 'set_policy', 'Unsupported treasury operation.');
  validatePolicy(args.owners, args.threshold, treasury);
  return { kind: 'policy', owners: args.owners, threshold: args.threshold };
}

export async function encodeTransfer(treasury: string, koin: string, to: string, raw: bigint): Promise<any> {
  address(to); requireValue(to !== treasury, 'The treasury cannot pay itself.');
  const op = await new Contract({ id: koin, abi: KOIN_ABI }).encodeOperation({ name: 'transfer', args: { from: treasury, to, value: raw.toString() } });
  return op;
}
export async function encodePolicy(treasury: string, owners: string[], threshold: number): Promise<any> {
  validatePolicy(owners, threshold, treasury);
  return new Contract({ id: treasury, abi: TREASURY_ABI }).encodeOperation({ name: 'set_policy', args: { owners, threshold } });
}

/// Signatures: Koinos compact recoverable form, header 31-34, canonical low-s.
export function signatureShape(signature: string): void {
  const curveN = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const bytes = b64(signature, 65); const r = BigInt('0x' + bytes.subarray(1, 33).toString('hex')); const s = BigInt('0x' + bytes.subarray(33).toString('hex'));
  requireValue(bytes[0] >= 31 && bytes[0] <= 34 && r > 0n && r < curveN && s > 0n && s <= curveN / 2n, 'Malformed or noncanonical signature.');
}
export const sameJson = (a: any, b: any): boolean => canonical(a) === canonical(b);
export { RefusalError };
