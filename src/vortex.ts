import { Abi, Contract, Provider, Signer, Transaction, utils } from 'koilib';
import * as fs from 'fs';
import * as path from 'path';
import { canonical, objectKeys, privateDirectory, readSafe, RefusalError, requireValue, strictJson, writeExclusive } from './secure-files';
import { actionHash, address, b64, bytesField, decodeExact, DELAY_MS, entryPoint, kernel, nonceValue, reviewedAbi, sha, transactionId, uint, varint, VORTEX_PIN, VORTEX_REPOSITORY, WINDOW_MS } from './vortex-protocol';

export interface VortexManifest {
  schema: number; source: { repository: string; commit: string; variant: string; adapterSha256: string | null };
  network: { name: string; chainId: string };
  contract: { address: string; codeSha256: string; abiSha256: string };
  policy: { reviewed: boolean; admins: string[]; adminThreshold: number; recoveryThreshold: number; validators: string[]; payer: string; delayMs: string; actionWindowMs: string };
}
export interface VortexPackage { schema: number; manifestSha256: string; abiSha256: string; transaction: any; snapshot: any; }
export interface VortexContext { manifest: VortexManifest; manifestSha256: string; abiSha256: string; abi: Abi; contract: Contract; }
export interface Review { id: string; chain: string; contract: string; header: any; payer: string; nonce: string; manaLimit: string; action: any; authority: string; required: number; admins: string[]; signers: string[]; adminSignatures: number; payerSigned: boolean; status: string; proposal: any; snapshot: any; }

const PUBLIC_CHAINS = ['EiBZK_GGVP0H_fXVAM3j6EAuz3-B-l3ejxRSewi7qIBfSA==', 'EiAIKVvm6-V2qmsmUvPJy09vCCLbtn9lHFpwrJbcTIEWRQ==', 'EiBncD4pKRIQWco_WRqo5Q-xnXR7JuO3PtZv983mKdKHSQ=='];
const hexHash = (v: any) => requireValue(typeof v === 'string' && /^[0-9a-f]{64}$/.test(v), 'Invalid SHA-256 binding.');
function identities(list: any, min: number, max: number): string[] {
  requireValue(Array.isArray(list) && list.length >= min && list.length <= max, 'Invalid membership count.'); list.forEach(address);
  requireValue(new Set(list).size === list.length, 'Duplicate member identities.'); return list;
}
const sameSet = (a: string[], b: string[]) => canonical([...a].sort()) === canonical([...b].sort());
export function validateManifest(m: VortexManifest): void {
  objectKeys(m, ['schema', 'source', 'network', 'contract', 'policy']); objectKeys(m.source, ['repository', 'commit', 'variant', 'adapterSha256']);
  objectKeys(m.network, ['name', 'chainId']); objectKeys(m.contract, ['address', 'codeSha256', 'abiSha256']);
  objectKeys(m.policy, ['reviewed', 'admins', 'adminThreshold', 'recoveryThreshold', 'validators', 'payer', 'delayMs', 'actionWindowMs']);
  requireValue(m.schema === 1 && m.source.repository === VORTEX_REPOSITORY && m.source.commit === VORTEX_PIN, 'Unreviewed Vortex release.');
  requireValue(['pinned-migration', 'fresh-initializer'].includes(m.source.variant), 'Unsupported contract variant.');
  if (m.source.variant === 'fresh-initializer') hexHash(m.source.adapterSha256); else requireValue(m.source.adapterSha256 === null, 'Unexpected source adapter.');
  requireValue(m.network.name === 'local' && !PUBLIC_CHAINS.includes(m.network.chainId), 'This qualification build only supports isolated local chains.'); b64(m.network.chainId, 34);
  address(m.contract.address); requireValue(m.contract.address !== '1aqHtNRDkiAZeFtuM8fRFuurcje6eHqF8', 'Existing production bridge is prohibited.');
  hexHash(m.contract.codeSha256); hexHash(m.contract.abiSha256);
  const p = m.policy; requireValue(p.reviewed === true, 'Policy is not marked reviewed (this declaration is not proof of on-chain authority).');
  identities(p.admins, 3, 19); identities(p.validators, 3, 19); address(p.payer);
  requireValue(Number.isInteger(p.adminThreshold) && p.adminThreshold >= Math.floor(p.admins.length / 2) + 1 && p.adminThreshold < p.admins.length, 'Invalid administration threshold.');
  requireValue(Number.isInteger(p.recoveryThreshold) && p.recoveryThreshold > p.adminThreshold && p.recoveryThreshold <= p.admins.length, 'Invalid recovery threshold.');
  const control = [m.contract.address, p.payer, ...p.admins, ...p.validators]; requireValue(new Set(control).size === control.length, 'Bridge, payer, administrators and validators must be separate identities.');
  requireValue(uint(p.delayMs) === DELAY_MS && uint(p.actionWindowMs) === WINDOW_MS, 'Only the reviewed 48-hour delay / 24-hour execution window is qualified.');
}
export function loadVortex(manifestFile: string, abiFile: string): VortexContext {
  const manifestText = readSafe(manifestFile); const m = strictJson(manifestText); validateManifest(m);
  const abiText = readSafe(abiFile); requireValue(sha(abiText) === m.contract.abiSha256, 'ABI hash does not match the reviewed manifest.');
  const abi = reviewedAbi(strictJson(abiText), m.source.variant);
  return { manifest: m, manifestSha256: sha(manifestText), abiSha256: sha(abiText), abi, contract: new Contract({ id: m.contract.address, abi }) };
}
export function readPackage(file: string): VortexPackage { return strictJson(readSafe(file)); }

function snapshotValid(ctx: VortexContext, snapshot: any): void {
  objectKeys(snapshot, ['config', 'paused', 'admins', 'validators', 'head', 'proposal']);
  const p = ctx.manifest.policy; const c = snapshot.config;
  const fields = ['migrated', 'migrationFinalized', 'ethBridge', 'ethChain', 'adminThreshold', 'depositNonce', 'pauseNonce', 'adminCount', 'setupFrozenAt', 'epoch', 'proposalNonce', 'recoveryThreshold', 'pausedAt'];
  if (ctx.manifest.source.variant === 'fresh-initializer') fields.push('freshDeployment'); objectKeys(c, fields);
  requireValue(c.migrated === true && typeof c.migrationFinalized === 'boolean' && typeof snapshot.paused === 'boolean', 'Bridge initialization/state is invalid.');
  requireValue(/^0x[0-9a-f]{40}$/.test(c.ethBridge) && c.ethBridge !== '0x' + '00'.repeat(20) && Number.isInteger(c.ethChain) && c.ethChain > 1, 'Invalid remote bridge domain.');
  if (fields.includes('freshDeployment')) requireValue(c.freshDeployment === true, 'Not the reviewed fresh deployment.');
  ['depositNonce', 'pauseNonce', 'setupFrozenAt', 'epoch', 'proposalNonce', 'pausedAt'].forEach(k => uint(c[k]));
  requireValue(c.adminThreshold === p.adminThreshold && c.recoveryThreshold === p.recoveryThreshold && c.adminCount === p.admins.length, 'Deployed thresholds differ from policy.');
  requireValue(sameSet(identities(snapshot.admins, 3, 19), p.admins) && sameSet(identities(snapshot.validators, 3, 19), p.validators), 'Deployed membership differs from policy.');
  objectKeys(snapshot.head, ['id', 'height', 'time', 'lib']); requireValue(/^0x1220[0-9a-f]{64}$/.test(snapshot.head.id), 'Invalid read anchor.');
  uint(snapshot.head.height); uint(snapshot.head.time); requireValue(uint(snapshot.head.lib) <= uint(snapshot.head.height), 'Invalid irreversible height.');
  if (snapshot.proposal !== null) {
    objectKeys(snapshot.proposal, ['hash', 'eta', 'nonce', 'epoch', 'kind']); requireValue(/^0x1220[0-9a-f]{64}$/.test(snapshot.proposal.hash), 'Invalid proposal hash.');
    ['eta', 'nonce', 'epoch'].forEach(k => uint(snapshot.proposal[k])); requireValue([0, 1].includes(snapshot.proposal.kind), 'Invalid proposal kind.');
  }
}
async function operationReview(ctx: VortexContext, call: any, snapshot: any) {
  const decoded = await decodeExact(ctx.contract, call); const { name, args } = decoded;
  requireValue(['pause', 'unpause', 'recover_validators', 'propose', 'cancel'].includes(name), 'Unsupported V2 action. No arbitrary-call bypass is provided.');
  let authority = 'administration'; let proposalHash: string | null = null; let inner: any = null;
  if (name === 'pause') {
    requireValue(args.expiry === '0' && (!args.signatures || args.signatures.length === 0), 'Validator pause signatures are a different authority and are not supported here.');
    requireValue(!snapshot.paused, 'Bridge is already paused.');
  }
  if (name === 'propose') {
    inner = await decodeExact(ctx.contract, { contract_id: call.contract_id, entry_point: args.entryPoint, args: utils.encodeBase64url(Buffer.from(String(args.args).replace(/^0x/, ''), 'hex')) });
    requireValue(['unpause', 'recover_validators'].includes(inner.name), 'Unsupported proposed action.');
    proposalHash = actionHash(args.entryPoint, utils.encodeBase64url(Buffer.from(String(args.args).replace(/^0x/, ''), 'hex')));
    if (inner.name === 'recover_validators') authority = 'recovery';
  }
  if (name === 'recover_validators') authority = 'recovery';
  if (name === 'recover_validators' || inner?.name === 'recover_validators') {
    const validators = identities((inner || decoded).args.validators, 3, 19);
    const excluded = [ctx.manifest.contract.address, ctx.manifest.policy.payer, ...ctx.manifest.policy.admins];
    requireValue(!validators.some(v => excluded.includes(v)), 'Recovery validators cannot be administrators, the bridge or payer.');
  }
  if (name === 'unpause' || inner?.name === 'unpause') {
    requireValue(snapshot.paused && snapshot.config.migrationFinalized, 'Unpause requires a paused, finalized bridge.');
  }
  if (name === 'unpause' || name === 'recover_validators') proposalHash = actionHash(call.entry_point, call.args);
  if (name === 'cancel') {
    requireValue(args.expiry === '0' && (!args.signatures || args.signatures.length === 0), 'Validator veto signatures are not administrator signatures.');
    proposalHash = args.actionHash; requireValue(snapshot.proposal?.hash === proposalHash && uint(snapshot.proposal.eta) > 0n, 'Cancellation requires a reviewed existing proposal.');
    if (snapshot.proposal.kind === 1) authority = 'recovery';
  }
  const required = authority === 'recovery' ? ctx.manifest.policy.recoveryThreshold : ctx.manifest.policy.adminThreshold;
  const proposal = snapshot.proposal;
  requireValue(!proposalHash || proposal?.hash === proposalHash, 'Proposal-state binding missing or changed.');
  const delayed = ['unpause', 'recover_validators'].includes(name) && uint(snapshot.config.setupFrozenAt) > 0n;
  const now = uint(snapshot.head.time);
  if (delayed) {
    requireValue(proposal && uint(proposal.eta) > 0n && proposal.epoch === snapshot.config.epoch && proposal.kind === (authority === 'recovery' ? 1 : 0), 'Missing, consumed or stale proposal.');
    requireValue(now >= uint(proposal.eta), 'Proposal delay has not elapsed.'); requireValue(now <= uint(proposal.eta) + WINDOW_MS, 'Proposal execution window expired.');
  }
  if (name === 'unpause') requireValue(now >= uint(snapshot.config.pausedAt) + DELAY_MS, 'Latest pause still has a 48-hour delay.');
  if (name === 'propose' && proposal && uint(proposal.eta) > 0n) requireValue(proposal.epoch !== snapshot.config.epoch || now > uint(proposal.eta) + WINDOW_MS, 'Action already has a live proposal.');
  return { ...decoded, inner, authority, required, proposalHash, delayed };
}
export async function reviewPackage(ctx: VortexContext, pkg: VortexPackage): Promise<Review> {
  objectKeys(pkg, ['schema', 'manifestSha256', 'abiSha256', 'transaction', 'snapshot']);
  requireValue(pkg.schema === 1 && pkg.manifestSha256 === ctx.manifestSha256 && pkg.abiSha256 === ctx.abiSha256, 'Package manifest/ABI binding changed.');
  snapshotValid(ctx, pkg.snapshot); const tx = pkg.transaction;
  requireValue(transactionId(tx) === tx.id, 'Transaction ID does not match the exact body.');
  requireValue(tx.header.chain_id === ctx.manifest.network.chainId && tx.header.payer === ctx.manifest.policy.payer && tx.operations[0].call_contract.contract_id === ctx.manifest.contract.address, 'Wrong chain, payer or contract.');
  const action = await operationReview(ctx, tx.operations[0].call_contract, pkg.snapshot);
  requireValue(tx.signatures.length <= ctx.manifest.policy.admins.length + 1, 'Too many signatures.');
  const curveN = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  for (const signature of tx.signatures) {
    const bytes = b64(signature, 65); const r = BigInt('0x' + bytes.subarray(1, 33).toString('hex')); const s = BigInt('0x' + bytes.subarray(33).toString('hex'));
    requireValue(bytes[0] >= 31 && bytes[0] <= 34 && r > 0n && r < curveN && s > 0n && s <= curveN / 2n, 'Malformed or noncanonical signature.');
  }
  let signers: string[]; try { signers = await Signer.recoverAddresses(tx); } catch { throw new RefusalError('Invalid transaction signature.'); }
  const allowed = [...ctx.manifest.policy.admins, ctx.manifest.policy.payer];
  requireValue(new Set(signers).size === signers.length && signers.every(s => allowed.includes(s)), 'Duplicate or unknown signing identity.');
  const count = signers.filter(s => ctx.manifest.policy.admins.includes(s)).length; const payerSigned = signers.includes(ctx.manifest.policy.payer);
  const status = count >= action.required && payerSigned ? 'signature-requirements-satisfied' : signers.length ? 'partially-signed' : 'prepared';
  const proposalExists = pkg.snapshot.proposal && uint(pkg.snapshot.proposal.eta) > 0n;
  return { id: tx.id, chain: tx.header.chain_id, contract: ctx.manifest.contract.address, header: tx.header, payer: tx.header.payer, nonce: nonceValue(tx.header.nonce).toString(), manaLimit: tx.header.rc_limit, action, authority: action.authority, required: action.required, admins: ctx.manifest.policy.admins, signers, adminSignatures: count, payerSigned, status,
    proposal: pkg.snapshot.proposal ? { ...pkg.snapshot.proposal, exists: !!proposalExists, executionDeadline: proposalExists ? (uint(pkg.snapshot.proposal.eta) + WINDOW_MS).toString() : null, delayMs: ctx.manifest.policy.delayMs, earliestPossibleEta: action.name === 'propose' ? (uint(pkg.snapshot.head.time) + DELAY_MS).toString() : null, etaAssignedAtInclusion: action.name === 'propose' } : null, snapshot: pkg.snapshot };
}
export async function appendSignature(ctx: VortexContext, pkg: VortexPackage, signer: Signer, expectedId: string, role: 'admin' | 'payer'): Promise<VortexPackage> {
  const review = await reviewPackage(ctx, pkg); const who = signer.getAddress();
  requireValue(expectedId === review.id, 'Confirm the exact reviewed transaction ID.');
  requireValue(role === 'admin' ? review.admins.includes(who) : who === ctx.manifest.policy.payer, 'Selected wallet is not the requested signer/authority.');
  requireValue(!review.signers.includes(who), 'This identity has already signed.');
  if (role === 'payer') requireValue(review.adminSignatures >= review.required, 'Administrator quorum is required before the separate payer-sign step.');
  const next = structuredClone(pkg); const before = canonical({ header: pkg.transaction.header, operations: pkg.transaction.operations, id: pkg.transaction.id });
  // Sign only the already verified digest; no SDK preparation, provider or Mana estimation can run.
  const signature = utils.encodeBase64url(await signer.signHash(Buffer.from(review.id.slice(6), 'hex')));
  next.transaction.signatures.push(signature);
  requireValue(before === canonical({ header: next.transaction.header, operations: next.transaction.operations, id: next.transaction.id }), 'Signing changed the transaction body.');
  const after = await reviewPackage(ctx, next);
  requireValue(after.signers.length === review.signers.length + 1 && after.signers[after.signers.length - 1] === who && pkg.transaction.signatures.every((s: string, i: number) => next.transaction.signatures[i] === s), 'Signing replaced or lost an existing signature.');
  return next;
}
export async function mergePackages(ctx: VortexContext, packages: VortexPackage[]): Promise<VortexPackage> {
  requireValue(packages.length >= 2 && packages.length <= 20, 'Merge needs 2-20 packages.'); const merged = structuredClone(packages[0]); const seen = new Set<string>(); merged.transaction.signatures = [];
  const binding = (p: VortexPackage) => canonical({ ...p, transaction: { ...p.transaction, signatures: [] } });
  for (const pkg of packages) {
    await reviewPackage(ctx, pkg); requireValue(binding(pkg) === binding(packages[0]), 'Cannot merge changed bodies or review snapshots.');
    for (const signature of pkg.transaction.signatures) { requireValue(!seen.has(signature), 'Duplicate signatures in merge inputs.'); seen.add(signature); merged.transaction.signatures.push(signature); }
  }
  await reviewPackage(ctx, merged); return merged;
}

const RPC_METHODS = new Set(['chain.get_chain_id', 'chain.get_head_info', 'chain.invoke_system_call', 'chain.read_contract', 'chain.get_account_nonce', 'chain.get_account_rc', 'chain.submit_transaction', 'contract_meta_store.get_contract_meta', 'transaction_store.get_transactions_by_id', 'block_store.get_blocks_by_id', 'block_store.get_blocks_by_height']);
export class VortexProvider extends Provider {
  constructor(readonly rpc: string) {
    super(rpc); const u = new URL(rpc);
    requireValue(u.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(u.hostname) && !u.username && !u.password && !u.hash && !u.search, 'Use an explicit loopback HTTP RPC for this local qualification build.');
  }
  async call<T = any>(method: string, params: any): Promise<T> {
    requireValue(RPC_METHODS.has(method), 'Unsupported Vortex RPC method.');
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 15000);
    try {
      const response = await fetch(this.rpc, { method: 'POST', redirect: 'error', signal: controller.signal, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
      requireValue(response.ok && response.body, 'RPC transport unavailable.');
      const reader = response.body.getReader(); const chunks: Uint8Array[] = []; let size = 0;
      for (;;) { const { value, done } = await reader.read(); if (done) break; size += value.length; requireValue(size <= 1024 * 1024, 'RPC response exceeds limit.'); chunks.push(value); }
      const result = strictJson(Buffer.concat(chunks).toString('utf8'));
      requireValue(result.id === 1 && result.jsonrpc === '2.0' && Object.prototype.hasOwnProperty.call(result, 'result') && !result.error, 'RPC refused the request or returned an invalid response.'); return result.result;
    } catch { throw new RefusalError('Vortex RPC request failed (response details withheld).'); }
    finally { clearTimeout(timer); controller.abort(); }
  }
}
async function getObject(provider: Provider, space: any, key: string, next = false): Promise<any> {
  const args = utils.encodeBase64url(await kernel.serialize({ space, key }, 'Query'));
  const caller = space.system ? {} : { caller_data: { caller: utils.encodeBase58(b64(space.zone, 25)), caller_privilege: 'user_mode' } };
  const response = await provider.call<any>('chain.invoke_system_call', { name: next ? 'get_next_object' : 'get_object', args, ...caller });
  const limit = space.system && space.id === 2 ? 900000 : 16384;
  return (await kernel.deserialize<any>(b64(response.value ?? '', undefined, limit), 'Result')).value;
}
async function bridgeResult(ctx: VortexContext, method: string, args?: any): Promise<any> {
  const outputType = ctx.abi.methods[method].return!;
  const operation = await ctx.contract.encodeOperation({ name: method, args: args || {} });
  const response = await ctx.contract.provider!.readContract(operation.call_contract!);
  const result: any = await ctx.contract.serializer!.deserialize(b64(response.result ?? ''), outputType);
  const type = outputType.split('.')[1];
  const fields = (ctx.abi.koilib_types as any).nested.bridge.nested[type].fields;
  objectKeys(result, [], Object.keys(fields));
  // koilib's display conversion omits false/zero scalars. Restore only the
  // protobuf defaults of the fixed reviewed result schema, never arbitrary fields.
  return Object.fromEntries(Object.entries<any>(fields).map(([name, spec]) => [name, result[name] ?? (spec.type === 'bool' ? false : spec.type === 'uint64' ? '0' : spec.type === 'uint32' ? 0 : '')]));
}
export async function chainBinding(ctx: VortexContext, provider: Provider): Promise<void> {
  requireValue(await provider.getChainId() === ctx.manifest.network.chainId, 'RPC chain does not match the reviewed network.');
  const key = utils.encodeBase64url(utils.decodeBase58(ctx.manifest.contract.address));
  const code = await getObject(provider, { system: true, id: 2 }, key);
  requireValue(code?.exists && sha(b64(code.value, undefined, 900000)) === ctx.manifest.contract.codeSha256, 'Deployed contract code does not match the reviewed hash.');
  const object = await getObject(provider, { system: true, id: 3 }, key); requireValue(object?.exists, 'Missing contract authority metadata.');
  const metadata = await kernel.deserialize<any>(object.value, 'Metadata');
  requireValue(metadata.hash === utils.encodeBase64url(Buffer.from('1220' + ctx.manifest.contract.codeSha256, 'hex')) && metadata.call && metadata.transaction && metadata.upload && !metadata.system, 'Contract code/authorization flags changed.');
  const { meta } = await provider.call<any>('contract_meta_store.get_contract_meta', { contract_id: ctx.manifest.contract.address });
  requireValue(typeof meta?.abi === 'string' && sha(meta.abi) === ctx.abiSha256, 'Deployed ABI does not match the reviewed ABI.');
}
async function members(ctx: VortexContext, provider: Provider, id: number): Promise<string[]> {
  const found: string[] = []; let key = ''; const space = { system: false, zone: utils.encodeBase64url(utils.decodeBase58(ctx.manifest.contract.address)), id };
  for (let n = 0; n < 20; n++) {
    const item = await getObject(provider, space, key, true); if (!item?.exists) return found;
    const next = item.key; const who = utils.encodeBase58(b64(next, 25)); address(who);
    requireValue(next !== key && !found.includes(who), 'Membership pagination did not advance.'); found.push(who); key = next;
  }
  throw new RefusalError('Membership exceeds the reviewed bound.');
}
async function snapshot(ctx: VortexContext, provider: Provider, call: any): Promise<any> {
  ctx.contract.provider = provider; const before = await provider.getHeadInfo();
  const config = await bridgeResult(ctx, 'get_config'); const paused = (await bridgeResult(ctx, 'is_paused')).value;
  const admins = await members(ctx, provider, 201); const validators = await members(ctx, provider, 100);
  const decoded = await decodeExact(ctx.contract, call); let hash: string | null = null;
  if (decoded.name === 'propose') hash = actionHash(decoded.args.entryPoint, utils.encodeBase64url(Buffer.from(decoded.args.args.replace(/^0x/, ''), 'hex')));
  if (['unpause', 'recover_validators'].includes(decoded.name)) hash = actionHash(call.entry_point, call.args);
  if (decoded.name === 'cancel') hash = decoded.args.actionHash;
  const proposal = hash ? { hash, ...await bridgeResult(ctx, 'get_proposal', { actionHash: hash }) } : null;
  const after = await provider.getHeadInfo(); requireValue(before.head_state_merkle_root === after.head_state_merkle_root, 'State changed during preflight; prepare/recheck again.');
  const snap = { config, paused, admins, validators, head: { id: after.head_topology.id, height: after.head_topology.height, time: after.head_block_time, lib: after.last_irreversible_block }, proposal };
  snapshotValid(ctx, snap); return snap;
}
export async function encodeAction(ctx: VortexContext, action: string, args: any, propose = false): Promise<any> {
  requireValue(['pause', 'unpause', 'recover_validators', 'cancel'].includes(action), 'Unsupported administration action.');
  if (['unpause', 'pause'].includes(action)) objectKeys(args, []);
  if (action === 'recover_validators') { objectKeys(args, ['validators']); identities(args.validators, 3, 19); }
  if (action === 'cancel') { objectKeys(args, ['actionHash']); requireValue(/^0x1220[0-9a-f]{64}$/.test(args.actionHash), 'Invalid cancellation hash.'); }
  const fields = action === 'pause' ? { expiry: '0', signatures: [] } : action === 'cancel' ? { ...args, expiry: '0', signatures: [] } : args;
  let op = await ctx.contract.encodeOperation({ name: action, args: fields });
  if (propose) {
    requireValue(['unpause', 'recover_validators'].includes(action), 'This action is not supported as a scheduled proposal.');
    op = await ctx.contract.encodeOperation({ name: 'propose', args: { entryPoint: op.call_contract!.entry_point, args: b64(op.call_contract!.args!).length ? '0x' + b64(op.call_contract!.args!).toString('hex') : '' } });
  }
  return op;
}
async function payerNonce(provider: Provider, payer: string): Promise<bigint> {
  const { nonce } = await provider.call<any>('chain.get_account_nonce', { account: payer }); return nonce ? nonceValue(nonce) : 0n;
}
export async function prepareVortex(ctx: VortexContext, provider: Provider, operation: any, rcLimit: string): Promise<VortexPackage> {
  await chainBinding(ctx, provider); const snap = await snapshot(ctx, provider, operation.call_contract);
  const mana = uint(await provider.getAccountRc(ctx.manifest.policy.payer)); requireValue(uint(rcLimit, true) <= mana, 'Payer Mana is insufficient.');
  const nextNonce = await payerNonce(provider, ctx.manifest.policy.payer) + 1n; requireValue(nextNonce <= 0xffffffffffffffffn, 'Payer nonce overflow.');
  const transaction = await Transaction.prepareTransaction({ header: { chain_id: ctx.manifest.network.chainId, payer: ctx.manifest.policy.payer, rc_limit: rcLimit, nonce: utils.encodeBase64url(Buffer.concat([Buffer.from([40]), varint(nextNonce)])) }, operations: [operation], signatures: [] });
  const pkg = { schema: 1, manifestSha256: ctx.manifestSha256, abiSha256: ctx.abiSha256, transaction, snapshot: snap };
  await reviewPackage(ctx, pkg); await chainBinding(ctx, provider); return pkg;
}
export async function preflightVortex(ctx: VortexContext, provider: Provider, pkg: VortexPackage): Promise<Review> {
  const review = await reviewPackage(ctx, pkg); requireValue(review.status === 'signature-requirements-satisfied', 'Missing administrator/recovery quorum or separate payer signature.');
  await chainBinding(ctx, provider); const fresh = await snapshot(ctx, provider, pkg.transaction.operations[0].call_contract);
  requireValue(canonical(fresh.config) === canonical(pkg.snapshot.config) && fresh.paused === pkg.snapshot.paused && canonical(fresh.proposal) === canonical(pkg.snapshot.proposal), 'Reviewed authority/proposal state is stale. Prepare a new separately reviewed transaction.');
  await operationReview(ctx, pkg.transaction.operations[0].call_contract, fresh);
  requireValue(nonceValue(pkg.transaction.header.nonce) === await payerNonce(provider, ctx.manifest.policy.payer) + 1n, 'Payer nonce is stale or already used; reconcile by transaction ID.');
  requireValue(uint(pkg.transaction.header.rc_limit, true) <= uint(await provider.getAccountRc(ctx.manifest.policy.payer)), 'Payer Mana is insufficient.'); return review;
}

async function resultingState(ctx: VortexContext, provider: Provider, pkg: VortexPackage, review: Review): Promise<any> {
  const before = await provider.getHeadInfo();
  ctx.contract.provider = provider; const config: any = await bridgeResult(ctx, 'get_config'); const paused = (await bridgeResult(ctx, 'is_paused')).value;
  const adminMembers = await members(ctx, provider, 201); const validatorMembers = await members(ctx, provider, 100);
  requireValue(config.adminThreshold === ctx.manifest.policy.adminThreshold && config.recoveryThreshold === ctx.manifest.policy.recoveryThreshold && sameSet(adminMembers, ctx.manifest.policy.admins), 'Resulting authority changed unexpectedly.');
  let proposal: any = null; const action = review.action;
  if (action.proposalHash) proposal = await bridgeResult(ctx, 'get_proposal', { actionHash: action.proposalHash });
  if (action.name === 'pause') requireValue(paused && uint(config.pauseNonce) === uint(pkg.snapshot.config.pauseNonce) + 1n, 'Pause result is not verified.');
  if (action.name === 'unpause') requireValue(!paused && uint(proposal.eta) === 0n, 'Unpause result/proposal consumption is not verified.');
  if (action.name === 'recover_validators') requireValue(sameSet(validatorMembers, action.args.validators) && uint(proposal.eta) === 0n, 'Recovery membership/proposal consumption is not verified.');
  if (action.name === 'cancel') requireValue(uint(proposal.eta) === 0n, 'Cancellation result is not verified.');
  if (action.name === 'propose') requireValue(uint(proposal.eta) >= uint(pkg.snapshot.head.time) + DELAY_MS && proposal.epoch === config.epoch && proposal.kind === (action.authority === 'recovery' ? 1 : 0) && uint(proposal.nonce) === uint(pkg.snapshot.config.proposalNonce) + 1n, 'Proposal schedule/epoch/nonce is not verified.');
  const after = await provider.getHeadInfo();
  requireValue(before.head_state_merkle_root === after.head_state_merkle_root, 'State changed during result verification; reconcile again.');
  return { config, paused, admins: adminMembers, validators: validatorMembers, proposal };
}
export async function reconcileVortex(ctx: VortexContext, provider: Provider, pkg: VortexPackage): Promise<any> {
  const review = await reviewPackage(ctx, pkg); await chainBinding(ctx, provider);
  const records = await provider.getTransactionsById([review.id]); const record = records.transactions?.find(t => t.transaction?.id === review.id);
  if (!record?.containing_blocks?.length) return { status: 'submission-outcome-unknown', id: review.id, message: 'No canonical inclusion proved. Do not rebuild or resend automatically.' };
  const head = await provider.getHeadInfo();
  for (const id of record.containing_blocks) {
    const blocks = await provider.getBlocksById([id], { returnBlock: true, returnReceipt: true }); const block = blocks.block_items?.find(b => b.block_id === id);
    if (!block?.block || !block.receipt) continue;
    const height = uint(block.block_height); requireValue(height <= BigInt(Number.MAX_SAFE_INTEGER), 'Block height exceeds supported range.');
    const canonicalBlocks = await provider.getBlocks(Number(height), 1, head.head_topology.id, { returnBlock: false, returnReceipt: false });
    if (canonicalBlocks[0]?.block_id !== id) continue;
    const included = block.block.transactions?.find(t => t.id === review.id); const receipt = block.receipt.transaction_receipts?.find(t => t.id === review.id);
    requireValue(included && receipt, 'Inclusion transaction or receipt does not match the reviewed package.');
    const exact = structuredClone(included);
    // Native protobuf JSON omits empty call args. That one known wire default
    // is equivalent to the SDK's empty string; every other body field stays exact.
    if (exact.operations?.length === 1 && exact.operations[0].call_contract && !Object.prototype.hasOwnProperty.call(exact.operations[0].call_contract, 'args')) exact.operations[0].call_contract.args = '';
    requireValue(canonical(exact) === canonical(pkg.transaction) && transactionId(exact) === review.id, 'Inclusion transaction or receipt does not match the reviewed package.');
    if (receipt.reverted) return { status: 'reverted', id: review.id, block: id, height: block.block_height };
    if (uint(head.last_irreversible_block) < height) return { status: 'included-successfully', id: review.id, block: id, height: block.block_height, irreversible: false };
    const result = await resultingState(ctx, provider, pkg, review);
    const finalHead = await provider.getHeadInfo(); const finalCanonical = await provider.getBlocks(Number(height), 1, finalHead.head_topology.id, { returnBlock: false, returnReceipt: false });
    requireValue(finalCanonical[0]?.block_id === id && uint(finalHead.last_irreversible_block) >= height, 'Canonical finality changed during reconciliation.');
    return { status: 'irreversible-and-state-verified', id: review.id, block: id, height: block.block_height, result };
  }
  return { status: 'submission-outcome-unknown', id: review.id, message: 'No canonical inclusion proved. Reconcile again; do not automatically resend.' };
}
export async function submitVortex(ctx: VortexContext, provider: Provider, pkg: VortexPackage, journalDir: string, confirmedId: string, timeoutMs: number): Promise<any> {
  const review = await preflightVortex(ctx, provider, pkg); requireValue(confirmedId === review.id, 'Confirm the exact transaction ID for submission.');
  const dir = privateDirectory(journalDir); const intent = path.join(dir, review.id.slice(2) + '.json');
  requireValue(!fs.existsSync(intent), 'This transaction already has a submission intent. Reconcile by ID before considering any manual retry.');
  // Persist the exact signed package before network I/O; an interrupted send is uncertain, never auto-retried.
  writeExclusive(intent, { schema: 1, status: 'submission-outcome-unknown', package: pkg });
  let response: any;
  try { response = await provider.call('chain.submit_transaction', { transaction: pkg.transaction, broadcast: true }); }
  catch { return { status: 'submission-outcome-unknown', id: review.id, message: 'Send result is unknown. Use vortex reconcile with this exact package.' }; }
  if (response?.receipt?.id !== review.id || response.receipt.rpc_error) return { status: 'submission-outcome-unknown', id: review.id };
  if (response.receipt.reverted) return { status: 'reverted', id: review.id };
  const end = Date.now() + timeoutMs; let result: any = { status: 'submission-outcome-unknown', id: review.id };
  do {
    try { result = await reconcileVortex(ctx, provider, pkg); } catch { return { status: 'submission-outcome-unknown', id: review.id, message: 'Readback failed. Reconcile; do not resend.' }; }
    if (['irreversible-and-state-verified', 'reverted'].includes(result.status)) return result;
    if (Date.now() >= end) return result;
    await new Promise(resolve => setTimeout(resolve, 500));
  } while (Date.now() <= end);
  return result;
}
