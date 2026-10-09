import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { Contract, Provider, Serializer, Signer, Transaction, utils } from 'koilib';
import { canonical, objectKeys, privateDirectory, readSafe, RefusalError, requireValue, safePath, strictJson, writeExclusive } from './secure-files';
import { address, b64, kernel, nonceValue, sha, transactionId, uint, varint } from './vortex-protocol';
import { canonicalBlock, corroborate } from './vortex-network';
import { canonicalOwners, deployTransactionId, encodePolicy, encodeTransfer, KOIN_ABI, MAX_OWNERS, MIN_OWNERS, reviewOperation, signatureShape, TEMPLATE_NAME, TEMPLATE_VERSION, TREASURY_ABI, TreasuryAction, validatePolicy } from './multisig-protocol';
import { authenticateReview, MultisigProfile, MultisigProvider, PUBLIC_FUND, PUBLIC_KOIN, stableTreasuryRead, validateNetwork } from './multisig-network';

const hex64 = (v: any) => requireValue(typeof v === 'string' && /^[0-9a-f]{64}$/.test(v), 'Invalid SHA-256 binding.');
const blockIdShape = (v: any) => requireValue(typeof v === 'string' && /^0x1220[0-9a-f]{64}$/.test(v), 'Invalid block or transaction ID.');
const encodeNonce = (n: bigint) => utils.encodeBase64url(Buffer.concat([Buffer.from([40]), varint(n)]));

// ------------------------------------------------------------------------------------------------- manifest
export interface MultisigContext { manifest: any; manifestSha256: string; profile: MultisigProfile; treasury: string; koin: string; }
export function validateManifest(m: any): MultisigProfile {
  objectKeys(m, ['schema', 'kind', 'network', 'token', 'treasury', 'policy']);
  requireValue(m.schema === 1 && m.kind === 'kcli-multisig-treasury', 'Not a kcli multisig treasury manifest.');
  const profile = validateNetwork(m.network);
  objectKeys(m.token, ['symbol', 'contract', 'decimals']); address(m.token.contract);
  requireValue(m.token.symbol === 'KOIN' && m.token.decimals === 8, 'Only KOIN is supported.');
  if (profile !== 'local') requireValue(m.token.contract === PUBLIC_KOIN[profile], 'KOIN binding differs from the reviewed network profile.');
  const t = m.treasury; objectKeys(t, ['address', 'template', 'templateVersion', 'codeSha256', 'abiSha256', 'sourceSha256', 'inputsSha256', 'bootstrap']);
  address(t.address); requireValue(t.template === TEMPLATE_NAME && t.templateVersion === TEMPLATE_VERSION, 'Unsupported contract template.');
  [t.codeSha256, t.abiSha256, t.sourceSha256, t.inputsSha256].forEach(hex64);
  objectKeys(t.bootstrap, ['transactionId', 'blockId', 'height']); blockIdShape(t.bootstrap.transactionId); blockIdShape(t.bootstrap.blockId); uint(t.bootstrap.height, true);
  requireValue(t.address !== m.token.contract, 'Treasury and token must differ.');
  objectKeys(m.policy, ['owners', 'threshold', 'version']); validatePolicy(m.policy.owners, m.policy.threshold, t.address); uint(m.policy.version);
  return profile;
}
export function loadManifest(file: string, review?: string, reviewKey?: string): MultisigContext {
  const text = readSafe(file); const manifest = strictJson(text); const profile = validateManifest(manifest);
  if (profile === 'mainnet') authenticateReview(text, review, reviewKey, 'manifest');
  else requireValue(!review && !reviewKey, 'Review attestations are only used with Mainnet manifests.');
  return { manifest, manifestSha256: sha(text), profile, treasury: manifest.treasury.address, koin: manifest.token.contract };
}

// ------------------------------------------------------------------------------------------ transaction package
export interface MultisigPackage { schema: number; kind: string; manifestSha256: string; note: string | null; transaction: any; snapshot: any; }
export interface Review { id: string; network: string; chainId: string; treasury: string; nonce: string; rcLimit: string; action: TreasuryAction; owners: string[]; threshold: number; policyVersion: string; signers: string[]; missing: number; status: string; note: { text: string | null; signed: false }; snapshot: any; warnings: string[]; }
export function readPackage(file: string): any { return strictJson(readSafe(file)); }
function validateHead(h: any): void {
  objectKeys(h, ['id', 'height', 'time', 'lib']); blockIdShape(h.id); uint(h.height); uint(h.time); requireValue(uint(h.lib) <= uint(h.height), 'Invalid irreversible height.');
}
function validateSnapshot(s: any): void {
  objectKeys(s, ['head', 'nonce', 'balance', 'mana', 'policyVersion']); validateHead(s.head);
  [s.nonce, s.balance, s.mana, s.policyVersion].forEach(v => uint(v));
}
async function recoverSigners(tx: any, max: number): Promise<string[]> {
  requireValue(Array.isArray(tx.signatures) && tx.signatures.length <= max, 'Too many signatures.');
  tx.signatures.forEach(signatureShape);
  let signers: string[]; try { signers = await Signer.recoverAddresses(tx); } catch { throw new RefusalError('Invalid transaction signature.'); }
  requireValue(signers.length === tx.signatures.length && new Set(signers).size === signers.length, 'Duplicate signing identity.');
  return signers;
}
export async function reviewPackage(ctx: MultisigContext, pkg: MultisigPackage): Promise<Review> {
  objectKeys(pkg, ['schema', 'kind', 'manifestSha256', 'note', 'transaction', 'snapshot']);
  requireValue(pkg.schema === 1 && pkg.kind === 'kcli-multisig-transaction', 'Not a multisig transaction package (deployment packages use the deploy commands).');
  requireValue(pkg.manifestSha256 === ctx.manifestSha256, 'Package was prepared for a different manifest.');
  requireValue(pkg.note === null || (typeof pkg.note === 'string' && /^[\x20-\x7e]{1,200}$/.test(pkg.note)), 'Invalid note.');
  validateSnapshot(pkg.snapshot); const m = ctx.manifest, tx = pkg.transaction;
  requireValue(pkg.snapshot.policyVersion === m.policy.version, 'Package was prepared for a different policy version; distribute a verified manifest snapshot first.');
  requireValue(transactionId(tx) === tx.id, 'Transaction ID does not match the exact body.');
  requireValue(tx.header.chain_id === m.network.chainId && tx.header.payer === ctx.treasury, 'Wrong chain or payer.');
  const nonce = nonceValue(tx.header.nonce); requireValue(nonce === uint(pkg.snapshot.nonce) + 1n, 'Nonce is not the next treasury nonce of the snapshot.');
  const action = await reviewOperation(tx.operations[0].call_contract, ctx.treasury, ctx.koin);
  const signers = await recoverSigners(tx, m.policy.owners.length);
  requireValue(signers.every(s => m.policy.owners.includes(s)), 'A signature is not from a current owner.');
  const warnings: string[] = []; const rc = uint(tx.header.rc_limit, true);
  if (action.kind === 'transfer') {
    const raw = uint(action.raw!);
    if (raw > uint(pkg.snapshot.balance)) warnings.push('Snapshot balance is below the amount.');
    if (raw + rc > uint(pkg.snapshot.mana)) warnings.push('Snapshot Mana is below amount + RC limit (a KOIN transfer spends Mana).');
  } else if (rc > uint(pkg.snapshot.mana)) warnings.push('Snapshot Mana is below the RC limit.');
  warnings.push('Snapshot values are dated observations; submit performs fresh checks.');
  const status = signers.length >= m.policy.threshold ? 'quorum-ready' : signers.length ? 'partial' : 'prepared';
  return { id: tx.id, network: m.network.name, chainId: m.network.chainId, treasury: ctx.treasury, nonce: nonce.toString(), rcLimit: tx.header.rc_limit, action, owners: m.policy.owners, threshold: m.policy.threshold, policyVersion: m.policy.version, signers, missing: Math.max(0, m.policy.threshold - signers.length), status, note: { text: pkg.note, signed: false }, snapshot: pkg.snapshot, warnings };
}
const body = (p: any) => canonical({ ...p, transaction: { ...p.transaction, signatures: [] } });
export async function appendSignature(ctx: MultisigContext, pkg: MultisigPackage, signer: Signer, expectedId: string): Promise<MultisigPackage> {
  const review = await reviewPackage(ctx, pkg); const who = signer.getAddress();
  requireValue(expectedId === review.id, 'Confirm the exact reviewed transaction ID.');
  requireValue(review.owners.includes(who), 'Selected wallet is not a current owner.');
  requireValue(!review.signers.includes(who), 'This identity has already signed.');
  const next = structuredClone(pkg);
  // Sign only the verified digest; no SDK preparation, provider or Mana estimation runs.
  next.transaction.signatures.push(utils.encodeBase64url(await signer.signHash(Buffer.from(review.id.slice(6), 'hex'))));
  requireValue(body(next) === body(pkg), 'Signing changed the package body.');
  const after = await reviewPackage(ctx, next);
  requireValue(after.signers.length === review.signers.length + 1 && after.signers.includes(who) && pkg.transaction.signatures.every((s: string, i: number) => next.transaction.signatures[i] === s), 'Signing replaced or lost a signature.');
  return next;
}
export async function mergePackages(ctx: MultisigContext, packages: MultisigPackage[]): Promise<MultisigPackage> {
  requireValue(packages.length >= 2 && packages.length <= MAX_OWNERS, `Merge needs 2-${MAX_OWNERS} packages.`);
  const byIdentity = new Map<string, string>();
  for (const p of packages) {
    await reviewPackage(ctx, p); requireValue(body(p) === body(packages[0]), 'Cannot merge different transactions, snapshots or notes.');
    const signers = await recoverSigners(p.transaction, MAX_OWNERS);
    signers.forEach((who, i) => {
      const sig = p.transaction.signatures[i]; const known = byIdentity.get(who);
      requireValue(known === undefined || known === sig, 'Conflicting signatures from one identity.'); byIdentity.set(who, sig);
    });
  }
  const merged = structuredClone(packages[0]);
  // Deterministic order: owner address bytes.
  merged.transaction.signatures = [...byIdentity.entries()].sort((a, b) => Buffer.compare(Buffer.from(utils.decodeBase58(a[0])), Buffer.from(utils.decodeBase58(b[0])))).map(e => e[1]);
  await reviewPackage(ctx, merged); return merged;
}

// --------------------------------------------------------------------------------------------- chain reads
async function getObject(provider: Provider, space: any, key: string, next = false): Promise<any> {
  const args = utils.encodeBase64url(await kernel.serialize({ space, key }, 'Query'));
  const caller = space.system ? {} : { caller_data: { caller: utils.encodeBase58(b64(space.zone, 25)), caller_privilege: 'user_mode' } };
  const response = await provider.call<any>('chain.invoke_system_call', { name: next ? 'get_next_object' : 'get_object', args, ...caller });
  return (await kernel.deserialize<any>(b64(response.value ?? '', undefined, 900000), 'Result')).value || {};
}
async function readMethod(provider: Provider, id: string, abi: any, name: string, args: any = {}): Promise<any> {
  const contract = new Contract({ id, abi, provider }); const op = await contract.encodeOperation({ name, args });
  const response = await provider.call<any>('chain.read_contract', { contract_id: id, entry_point: op.call_contract!.entry_point, args: op.call_contract!.args });
  return contract.serializer!.deserialize(b64(response.result ?? '', undefined, 64000), abi.methods[name].return);
}
async function nonceOf(provider: Provider, account: string): Promise<bigint> {
  const { nonce } = await provider.call<any>('chain.get_account_nonce', { account }); return nonce ? nonceValue(nonce) : 0n;
}
/// Code identity = the kernel's contract metadata: the chain itself computed this sha2-256 multihash from the
/// uploaded bytes and stores it with the authority flags. (Reading the full bytecode through invoke_system_call
/// depends on each node's system-call buffer size and adds no trust over the same node's metadata.)
async function deployedCode(provider: Provider, account: string): Promise<{ codeSha256: string | null; meta: any }> {
  const key = utils.encodeBase64url(utils.decodeBase58(account));
  const object = await getObject(provider, { system: true, id: 3 }, key); if (!object.exists) return { codeSha256: null, meta: null };
  const meta = await kernel.deserialize<any>(object.value, 'Metadata'); const hash = b64(meta.hash ?? '', 34);
  requireValue(hash[0] === 0x12 && hash[1] === 0x20, 'Unexpected contract hash algorithm.');
  return { codeSha256: hash.subarray(2).toString('hex'), meta };
}
/// Contract storage written by Storage.Obj lives under the EMPTY key: a get_next_object('') scan alone misses it.
async function policySpaceEmpty(provider: Provider, account: string): Promise<boolean> {
  const space = { system: false, zone: utils.encodeBase64url(utils.decodeBase58(account)), id: 0 };
  return !(await getObject(provider, space, '')).exists && !(await getObject(provider, space, '', true)).exists;
}
async function allowanceCount(provider: Provider, koin: string, owner: string): Promise<number> {
  const r = await readMethod(provider, koin, KOIN_ABI, 'get_allowances', { owner, start: '', limit: 1, descending: false });
  return (r.allowances || []).length;
}
const FUND_ABI: any = { methods: { get_user_votes: { entry_point: 0, argument: 'fund.get_user_votes_arguments', return: 'fund.get_user_votes_result', read_only: true } },
  koilib_types: { nested: { fund: { nested: { get_user_votes_arguments: { fields: { voter: { type: 'bytes', id: 1, options: { '(koinos.btype)': 'ADDRESS' } } } }, vote_info: { fields: { project_id: { type: 'uint32', id: 1 }, weight: { type: 'uint32', id: 2 }, expiration: { type: 'uint64', id: 3, options: { jstype: 'JS_STRING' } } } }, get_user_votes_result: { fields: { votes: { rule: 'repeated', type: 'vote_info', id: 1 } } } } } } } };
FUND_ABI.methods.get_user_votes.entry_point = parseInt(sha('get_user_votes').slice(0, 8), 16);
async function fundVotes(provider: Provider, profile: MultisigProfile, account: string): Promise<number | null> {
  const fund = PUBLIC_FUND[profile]; if (!fund) return null;
  return ((await readMethod(provider, fund, FUND_ABI, 'get_user_votes', { voter: account })).votes || []).length;
}
async function readPolicy(provider: Provider, treasury: string): Promise<{ owners: string[]; threshold: number; version: string }> {
  const r = await readMethod(provider, treasury, TREASURY_ABI, 'get_policy');
  // koilib omits protobuf defaults; restore only those of the fixed schema.
  return { owners: r.owners || [], threshold: r.threshold || 0, version: r.version || '0' };
}

/// Code, metadata hash and all three override flags of the reviewed deployment, on the expected chain.
export async function chainBinding(ctx: MultisigContext, provider: Provider): Promise<void> {
  requireValue(await provider.getChainId() === ctx.manifest.network.chainId, 'RPC chain does not match the reviewed network.');
  const { codeSha256, meta } = await deployedCode(provider, ctx.treasury);
  requireValue(codeSha256 === ctx.manifest.treasury.codeSha256, 'Deployed treasury code does not match the reviewed hash.');
  requireValue(meta && meta.hash === utils.encodeBase64url(Buffer.from('1220' + codeSha256, 'hex')) && meta.call && meta.transaction && meta.upload && !meta.system, 'Treasury code hash or authority flags changed.');
}
function witnessOf(ctx: MultisigContext, provider: Provider): MultisigProvider | undefined {
  if (ctx.profile !== 'mainnet') return undefined;
  const p = provider as MultisigProvider; const urls = ctx.manifest.network.rpcs.map((r: any) => r.url);
  requireValue(p instanceof MultisigProvider && !p.readOnly && p.witness?.readOnly && p.rpc !== p.witness.rpc && urls.includes(p.rpc) && urls.includes(p.witness.rpc), 'Mainnet requires the two reviewed RPCs of the manifest.');
  return p.witness;
}
/// Stable read (protected treasury zone/code/nonce unchanged across the interval); on Mainnet also on the
/// independent witness, compared and corroborated at the common irreversible height.
async function observe<T>(ctx: MultisigContext, provider: Provider, read: (p: Provider) => Promise<T>, bind = true): Promise<{ value: T; head: any }> {
  const witness = witnessOf(ctx, provider);
  const collect = (p: Provider) => stableTreasuryRead(p, ctx.treasury, ctx.koin, !!witness, async () => { if (bind) await chainBinding(ctx, p); return read(p); });
  const primary = await collect(provider);
  if (witness) {
    const second = await collect(witness);
    requireValue(canonical(primary.value) === canonical(second.value), 'Independent RPCs disagree on the treasury state.');
    await corroborate(provider, witness, primary.head, second.head);
  }
  return { value: primary.value, head: primary.head };
}
async function treasuryState(ctx: MultisigContext, provider: Provider) {
  const observed = await observe(ctx, provider, async p => {
    const policy = await readPolicy(p, ctx.treasury); const nonce = await nonceOf(p, ctx.treasury);
    const balance = (await readMethod(p, ctx.koin, KOIN_ABI, 'balance_of', { owner: ctx.treasury })).value || '0';
    const mana = await p.getAccountRc(ctx.treasury); const allowances = await allowanceCount(p, ctx.koin, ctx.treasury);
    return { policy, nonce: nonce.toString(), balance, mana: String(mana), allowances };
  });
  const v = observed.value, h = observed.head;
  requireValue(v.allowances === 0, 'The treasury has KOIN allowances: compromised bootstrap. Stop and investigate.');
  const m = ctx.manifest.policy;
  requireValue(canonical(v.policy) === canonical({ owners: m.owners, threshold: m.threshold, version: m.version }), 'On-chain policy differs from the manifest; verify and distribute the current snapshot first.');
  return { ...v, head: { id: h.head_topology.id, height: h.head_topology.height, time: h.head_block_time, lib: h.last_irreversible_block } };
}
export async function treasuryInfo(ctx: MultisigContext, provider: Provider): Promise<any> {
  const s = await treasuryState(ctx, provider);
  const template = await readMethod(provider, ctx.treasury, TREASURY_ABI, 'get_template');
  return { network: ctx.manifest.network.name, treasury: ctx.treasury, manifestSha256: ctx.manifestSha256, codeSha256: ctx.manifest.treasury.codeSha256, flags: 'call,transaction,upload', template: { name: template.name, version: template.version }, policy: s.policy, nonce: s.nonce, balance: s.balance, mana: s.mana, allowances: s.allowances, head: s.head };
}

// ---------------------------------------------------------------------------------------- prepare / submit
export async function prepareAction(ctx: MultisigContext, provider: Provider, operation: any, rcLimit: string, note: string | null): Promise<MultisigPackage> {
  const rc = uint(rcLimit, true); await chainBinding(ctx, provider); const s = await treasuryState(ctx, provider);
  const action = await reviewOperation(operation.call_contract, ctx.treasury, ctx.koin);
  if (action.kind === 'transfer') { const raw = uint(action.raw!); requireValue(raw <= uint(s.balance), 'Treasury KOIN balance is insufficient.'); requireValue(raw + rc <= uint(s.mana), 'Treasury Mana does not cover amount + RC limit (a KOIN transfer spends Mana).'); }
  else requireValue(rc <= uint(s.mana), 'Treasury Mana does not cover the RC limit.');
  const next = uint(s.nonce) + 1n; requireValue(next <= 0xffffffffffffffffn, 'Nonce overflow.');
  const transaction = await Transaction.prepareTransaction({ header: { chain_id: ctx.manifest.network.chainId, payer: ctx.treasury, rc_limit: rc.toString(), nonce: encodeNonce(next) }, operations: [operation], signatures: [] });
  const pkg = { schema: 1, kind: 'kcli-multisig-transaction', manifestSha256: ctx.manifestSha256, note, transaction, snapshot: { head: s.head, nonce: s.nonce, balance: s.balance, mana: s.mana, policyVersion: s.policy.version } };
  await reviewPackage(ctx, pkg); await chainBinding(ctx, provider); return pkg;
}
export async function transferOperation(ctx: MultisigContext, to: string, raw: bigint): Promise<any> { return encodeTransfer(ctx.treasury, ctx.koin, to, raw); }
export async function policyOperation(ctx: MultisigContext, policy: any): Promise<any> {
  objectKeys(policy, ['owners', 'threshold']);
  return encodePolicy(ctx.treasury, canonicalOwners(policy.owners), policy.threshold);
}
export async function preflight(ctx: MultisigContext, provider: Provider, pkg: MultisigPackage): Promise<Review> {
  const review = await reviewPackage(ctx, pkg); requireValue(review.status === 'quorum-ready', `Missing owner approvals: ${review.missing} more needed.`);
  const s = await treasuryState(ctx, provider); const rc = uint(review.rcLimit, true);
  requireValue(uint(review.nonce) === uint(s.nonce) + 1n, 'Treasury nonce is stale or already used; reconcile by transaction ID before preparing anything new.');
  if (review.action.kind === 'transfer') { const raw = uint(review.action.raw!); requireValue(raw <= uint(s.balance) && raw + rc <= uint(s.mana), 'Fresh balance or Mana is insufficient; the amount is never changed automatically.'); }
  else requireValue(rc <= uint(s.mana), 'Fresh Mana is insufficient.');
  requireValue(await nonceOf(provider, ctx.treasury) === uint(s.nonce), 'Treasury nonce changed during preflight.');
  return { ...review, snapshot: { ...review.snapshot, fresh: s } };
}
/// Exact header and operations (hence the same ID). Signatures are checked independently: anyone holding the
/// package could broadcast a different valid subset (the ID does not cover signatures), which is still this
/// execution and must reconcile.
async function exactIncluded(block: any, expected: any, id: string, signaturesValid: (tx: any) => Promise<void>): Promise<any> {
  const included = block.block?.transactions?.find((t: any) => t.id === id), receipt = block.receipt?.transaction_receipts?.find((t: any) => t.id === id);
  requireValue(included && receipt && typeof (receipt.reverted ?? false) === 'boolean', 'Inclusion transaction or receipt does not match the package.');
  const exact = structuredClone(included); const want = structuredClone(expected);
  // Normalize only known protobuf-default omissions of the JSON renderer.
  const call = exact.operations?.[0]?.call_contract; if (call && !Object.prototype.hasOwnProperty.call(call, 'args')) call.args = '';
  requireValue(exact.id === id && canonical(exact.header) === canonical(want.header) && canonical(exact.operations) === canonical(want.operations), 'Included transaction differs from the reviewed package.');
  requireValue(Array.isArray(exact.signatures), 'Included transaction has no signatures.'); await signaturesValid(exact);
  return receipt;
}
const quorumSignatures = (ctx: MultisigContext) => async (tx: any) => {
  const signers = await recoverSigners(tx, ctx.manifest.policy.owners.length);
  requireValue(signers.every(s => ctx.manifest.policy.owners.includes(s)) && signers.length >= ctx.manifest.policy.threshold, 'Included signatures are not a quorum of the manifest policy.');
};
const bootstrapSignature = (treasury: string) => async (tx: any) => {
  const signers = await recoverSigners(tx, 1); requireValue(signers.length === 1 && signers[0] === treasury, 'Included bootstrap is not signed by the treasury address key.');
};
/// Canonical, irreversible inclusion of an exact transaction (corroborated on Mainnet), or an explicit unknown.
async function findIncluded(ctx: { profile: MultisigProfile }, provider: Provider, witness: MultisigProvider | undefined, id: string, expected: any, signaturesValid: (tx: any) => Promise<void>): Promise<any> {
  const records = await provider.getTransactionsById([id]); const record = records.transactions?.find((t: any) => t.transaction?.id === id);
  if (!record?.containing_blocks?.length) return { status: 'unknown', id, message: 'No canonical inclusion proved. Do not rebuild, re-sign or resend automatically.' };
  const head = await provider.getHeadInfo();
  for (const blockId of record.containing_blocks) {
    const blocks = await provider.getBlocksById([blockId], { returnBlock: true, returnReceipt: true }); const block = blocks.block_items?.find((b: any) => b.block_id === blockId);
    if (!block?.block || !block.receipt) continue;
    const height = uint(block.block_height); requireValue(height <= BigInt(Number.MAX_SAFE_INTEGER), 'Block height exceeds supported range.');
    if ((await canonicalBlock(provider, head, height)).block_id !== blockId) continue;
    const receipt = await exactIncluded(block, expected, id, signaturesValid);
    let irreversible = uint(head.last_irreversible_block) >= height;
    if (witness) {
      const witnessHead = await witness.getHeadInfo(); await corroborate(provider, witness, head, witnessHead, height);
      const other = await canonicalBlock(witness, witnessHead, height, true);
      const otherReceipt = await exactIncluded(other, expected, id, signaturesValid);
      requireValue(other.block_id === blockId && canonical({ r: otherReceipt.reverted ?? false, e: otherReceipt.events || [] }) === canonical({ r: receipt.reverted ?? false, e: receipt.events || [] }), 'Independent RPC disagrees on inclusion, receipt or events.');
      irreversible = irreversible && uint(witnessHead.last_irreversible_block) >= height;
    }
    // A reversible block can still be replaced: neither success nor failure is final before irreversibility.
    if (receipt.reverted) return { status: irreversible ? 'reverted' : 'included-reverted', id, block: blockId, height: block.block_height };
    return { status: irreversible ? 'irreversible' : 'included', id, block: blockId, height: block.block_height, receipt };
  }
  return { status: 'unknown', id, message: 'No canonical inclusion proved. Reconcile again; never resend automatically.' };
}
export async function reconcile(ctx: MultisigContext, provider: Provider, pkg: MultisigPackage): Promise<any> {
  const review = await reviewPackage(ctx, pkg); requireValue(review.status === 'quorum-ready', 'Only a quorum-ready package can have been executed.');
  await chainBinding(ctx, provider);
  const found = await findIncluded(ctx, provider, witnessOf(ctx, provider), review.id, pkg.transaction, quorumSignatures(ctx));
  if (found.status !== 'irreversible') return found;
  let result: any;
  if (review.action.kind === 'transfer') {
    const serializer = new Serializer(KOIN_ABI.koilib_types!);
    const events = (found.receipt.events || []).filter((e: any) => e.name === 'token.transfer_event' && e.source === ctx.koin);
    const decoded = await Promise.all(events.map((e: any) => serializer.deserialize(e.data, 'koin.transfer_event')));
    requireValue(decoded.length === 1 && (decoded[0] as any).from === ctx.treasury && (decoded[0] as any).to === review.action.to && (decoded[0] as any).value === review.action.raw, 'Transfer event does not match the reviewed payment.');
    result = { transferEvent: decoded[0] };
  } else {
    const p = (await observe(ctx, provider, q => readPolicy(q, ctx.treasury), false)).value;
    const expectedVersion = (uint(ctx.manifest.policy.version) + 1n).toString();
    if (canonical(p) !== canonical({ owners: review.action.owners, threshold: review.action.threshold, version: expectedVersion })) {
      return { status: 'unknown', id: review.id, message: 'Included, but the current policy is not the reviewed replacement (a later rotation may have followed). Investigate manually.' };
    }
    const manifest = structuredClone(ctx.manifest); manifest.policy = p; result = { policy: p, manifest };
  }
  for (const p of [provider, witnessOf(ctx, provider)].filter(Boolean) as Provider[]) {
    const final = await p.getHeadInfo();
    requireValue((await canonicalBlock(p, final, uint(found.height))).block_id === found.block && uint(final.last_irreversible_block) >= uint(found.height), 'Canonical finality changed during reconciliation.');
  }
  return { status: 'irreversible-and-verified', id: review.id, block: found.block, height: found.height, ...result };
}
/// One canonical private journal per chain and paying account under ~/.kcli (no per-call directory can be chosen
/// to sidestep it). An exclusive per-nonce lock stops a second local submission for the same treasury nonce.
export function journalDirectory(chainId: string, account: string): string {
  const root = path.join(os.homedir(), '.kcli'); privateDirectory(root, true);
  let dir = root; for (const part of ['multisig-journal', sha(chainId).slice(0, 16), address(account)]) { dir = path.join(dir, part); privateDirectory(dir, true); }
  return dir;
}
async function sendOnce(provider: Provider, transaction: any, id: string, record: any): Promise<string> {
  const dir = journalDirectory(transaction.header.chain_id, transaction.header.payer);
  const intent = path.join(dir, id.slice(2) + '.json'); const lock = path.join(dir, 'nonce-' + nonceValue(transaction.header.nonce).toString() + '.json');
  requireValue(!fs.existsSync(intent), 'This transaction already has a submission intent. Reconcile by ID; never resend automatically.');
  requireValue(!fs.existsSync(lock), 'Another transaction for this treasury nonce was already submitted from this machine. Reconcile it first.');
  writeExclusive(lock, { schema: 1, id });
  // Durable private intent BEFORE the network write: an interrupted send is uncertain, never retried.
  writeExclusive(intent, { schema: 1, status: 'submitted-unconfirmed', id, ...record });
  try {
    const response: any = await provider.call('chain.submit_transaction', { transaction, broadcast: true });
    if (response?.receipt?.id !== id || response.receipt.rpc_error) return 'submitted-unconfirmed';
    return response.receipt.reverted ? 'reverted' : 'submitted-unconfirmed';
  } catch { return 'submitted-unconfirmed'; }
}
export async function submit(ctx: MultisigContext, provider: Provider, pkg: MultisigPackage, confirmedId: string, waitMs: number): Promise<any> {
  const review = await preflight(ctx, provider, pkg); requireValue(confirmedId === review.id, 'Confirm the exact transaction ID for submission.');
  const sent = await sendOnce(provider, pkg.transaction, review.id, { kind: 'transaction', package: pkg });
  const end = Date.now() + waitMs; let result: any = { status: sent, id: review.id };
  for (;;) {
    try { result = await reconcile(ctx, provider, pkg); } catch { return { status: 'submitted-unconfirmed', id: review.id, message: 'Readback failed. Reconcile; do not resend.' }; }
    if (['irreversible-and-verified', 'reverted'].includes(result.status) || Date.now() >= end) return result.status === 'unknown' ? { ...result, status: 'submitted-unconfirmed' } : result;
    // included / included-reverted: keep reconciling until irreversible or the wait ends
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
}

// ------------------------------------------------------------------------------------------------ bootstrap
export interface DeployPackage { schema: number; kind: string; network: any; inputs: any; artifact: any; transaction: any; snapshot: any; }
function readBinarySafe(file: string, max: number): Buffer {
  const p = safePath(file); const fd = fs.openSync(p, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try { const st = fs.fstatSync(fd); requireValue(st.isFile() && st.size <= max && st.nlink === 1, 'Unsafe artifact file.'); return fs.readFileSync(fd); } finally { fs.closeSync(fd); }
}
export function validateInputs(inputs: any, network: any): void {
  objectKeys(inputs, ['schema', 'template', 'templateVersion', 'network', 'chainId', 'koinContract', 'treasury', 'owners', 'threshold']);
  requireValue(inputs.schema === 1 && inputs.template === TEMPLATE_NAME && inputs.templateVersion === TEMPLATE_VERSION, 'Unsupported template inputs.');
  const profile = validateNetwork(network);
  requireValue(inputs.network === profile && inputs.chainId === network.chainId, 'Artifact inputs were built for another network.');
  address(inputs.koinContract); address(inputs.treasury);
  if (profile !== 'local') requireValue(inputs.koinContract === PUBLIC_KOIN[profile], 'Artifact binds an unreviewed KOIN contract.');
  validatePolicy(inputs.owners, inputs.threshold, inputs.treasury);
}
function validateArtifact(a: any): void {
  objectKeys(a, ['schema', 'template', 'templateVersion', 'inputsSha256', 'sourceSha256', 'wasmSha256', 'wasmSize', 'abiSha256', 'toolchain']);
  requireValue(a.schema === 1 && a.template === TEMPLATE_NAME && a.templateVersion === TEMPLATE_VERSION && Number.isSafeInteger(a.wasmSize) && a.wasmSize > 0 && a.wasmSize <= 300000, 'Unsupported artifact manifest.');
  [a.inputsSha256, a.sourceSha256, a.wasmSha256, a.abiSha256].forEach(hex64);
  requireValue(a.toolchain && typeof a.toolchain === 'object' && /^[0-9a-f]{64}$/.test(a.toolchain.treeSha256), 'Artifact lacks the pinned toolchain hash.');
}
export function loadArtifact(dir: string, network: any): { inputs: any; artifact: any; wasm: Buffer; abi: string } {
  const base = safePath(dir);
  const artifact = strictJson(readSafe(path.join(base, 'artifact.json'))); validateArtifact(artifact);
  const inputsText = readSafe(path.join(base, 'inputs.json')); requireValue(sha(inputsText) === artifact.inputsSha256, 'inputs.json does not match the artifact manifest.');
  const inputs = strictJson(inputsText); validateInputs(inputs, network);
  const wasm = readBinarySafe(path.join(base, 'contract.wasm'), 300000); requireValue(sha(wasm) === artifact.wasmSha256 && wasm.length === artifact.wasmSize, 'contract.wasm does not match the artifact manifest.');
  const abi = readSafe(path.join(base, 'treasury.abi')); requireValue(sha(abi) === artifact.abiSha256, 'treasury.abi does not match the artifact manifest.');
  return { inputs, artifact, wasm, abi };
}
export async function reviewDeploy(pkg: DeployPackage): Promise<any> {
  objectKeys(pkg, ['schema', 'kind', 'network', 'inputs', 'artifact', 'transaction', 'snapshot']);
  requireValue(pkg.schema === 1 && pkg.kind === 'kcli-multisig-deploy', 'Not a multisig deployment package.');
  validateInputs(pkg.inputs, pkg.network); validateArtifact(pkg.artifact);
  requireValue(sha(JSON.stringify(pkg.inputs, null, 2) + '\n') === pkg.artifact.inputsSha256, 'Inputs do not match the artifact manifest.');
  const tx = pkg.transaction; requireValue(deployTransactionId(tx) === tx.id, 'Bootstrap ID does not match the exact body.');
  const up = tx.operations[0].upload_contract, t = pkg.inputs.treasury;
  requireValue(tx.header.chain_id === pkg.network.chainId && tx.header.payer === t && up.contract_id === t, 'Bootstrap must upload to, and be paid by, the treasury address itself.');
  requireValue(sha(b64(up.bytecode, undefined, 400000)) === pkg.artifact.wasmSha256 && sha(up.abi) === pkg.artifact.abiSha256, 'Upload bytes differ from the reviewed artifact.');
  requireValue(nonceValue(tx.header.nonce) === 1n, 'The bootstrap must be the first transaction the treasury address pays for.');
  objectKeys(pkg.snapshot, ['head', 'nonce', 'mana', 'balance']); validateHead(pkg.snapshot.head); requireValue(pkg.snapshot.nonce === '0', 'Snapshot shows a used address.'); uint(pkg.snapshot.mana); uint(pkg.snapshot.balance);
  const signers = await recoverSigners(tx, 1); requireValue(signers.every(s => s === t), 'Only the treasury address key signs the bootstrap.');
  return { id: tx.id, kind: 'bootstrap', network: pkg.network.name, chainId: pkg.network.chainId, treasury: t, koin: pkg.inputs.koinContract, owners: pkg.inputs.owners, threshold: pkg.inputs.threshold,
    wasmSha256: pkg.artifact.wasmSha256, abiSha256: pkg.artifact.abiSha256, sourceSha256: pkg.artifact.sourceSha256, toolchainTreeSha256: pkg.artifact.toolchain.treeSha256,
    flags: { call: true, transaction: true, upload: true }, rcLimit: tx.header.rc_limit, signed: signers.length === 1, status: signers.length ? 'bootstrap-signed' : 'prepared',
    reminder: 'Bootstrap approval authorizes this upload only. It is never a payment or member approval.' };
}
/// Mainnet bootstrap qualification: an Ed25519 review of the exact unsigned bootstrap (body without signatures),
/// under a different domain than manifest reviews, so it can never qualify payments.
export const bootstrapDigestText = (pkg: DeployPackage): string => body(pkg);
export function requireBootstrapReview(pkg: DeployPackage, review?: string, reviewKey?: string): void {
  if (validateNetwork(pkg.network) === 'mainnet') authenticateReview(bootstrapDigestText(pkg), review, reviewKey, 'bootstrap');
  else requireValue(!review && !reviewKey, 'Review attestations are only used with Mainnet profiles.');
}
/// The address must be unused: no nonce, code, metadata, stored policy, KOIN allowances or fund votes.
async function virgin(provider: Provider, profile: MultisigProfile, treasury: string, koin: string): Promise<void> {
  const witness = profile === 'mainnet' ? (provider as MultisigProvider).witness : undefined;
  if (profile === 'mainnet') requireValue(witness?.readOnly, 'Mainnet bootstrap requires the corroborating RPC.');
  for (const p of [provider, witness].filter(Boolean) as Provider[]) await virginOn(p, profile, treasury, koin);
  if (witness) await corroborate(provider, witness, await provider.getHeadInfo(), await witness.getHeadInfo());
}
async function virginOn(provider: Provider, profile: MultisigProfile, treasury: string, koin: string): Promise<void> {
  requireValue(await nonceOf(provider, treasury) === 0n, 'The treasury address has already paid for a transaction. Use a fresh key.');
  const { codeSha256, meta } = await deployedCode(provider, treasury); requireValue(!codeSha256 && !meta, 'The treasury address already has a contract.');
  requireValue(await policySpaceEmpty(provider, treasury), 'The treasury address already has contract storage.');
  requireValue(await allowanceCount(provider, koin, treasury) === 0, 'The treasury address has KOIN allowances.');
  requireValue(!await fundVotes(provider, profile, treasury), 'The treasury address has Koinos Fund votes.');
}
export async function prepareDeploy(dir: string, network: any, provider: Provider, rcLimit: string): Promise<DeployPackage> {
  const profile = validateNetwork(network); const { inputs, artifact, wasm, abi } = loadArtifact(dir, network);
  requireValue(await provider.getChainId() === network.chainId, 'RPC chain does not match the network profile.');
  const { codeSha256 } = await deployedCode(provider, inputs.koinContract); requireValue(codeSha256, 'The KOIN contract is not deployed on this chain.');
  await virgin(provider, profile, inputs.treasury, inputs.koinContract);
  const rc = uint(rcLimit, true); const mana = BigInt(await provider.getAccountRc(inputs.treasury)); requireValue(rc <= mana, 'Provision the treasury address with enough KOIN for the upload Mana first.');
  const balance = (await readMethod(provider, inputs.koinContract, KOIN_ABI, 'balance_of', { owner: inputs.treasury })).value || '0';
  const transaction = await Transaction.prepareTransaction({ header: { chain_id: network.chainId, payer: inputs.treasury, rc_limit: rc.toString(), nonce: encodeNonce(1n) },
    operations: [{ upload_contract: { contract_id: inputs.treasury, bytecode: utils.encodeBase64url(wasm), abi, authorizes_call_contract: true, authorizes_transaction_application: true, authorizes_upload_contract: true } }], signatures: [] });
  const head = await provider.getHeadInfo();
  const pkg = { schema: 1, kind: 'kcli-multisig-deploy', network, inputs, artifact, transaction, snapshot: { head: { id: head.head_topology.id, height: head.head_topology.height, time: head.head_block_time, lib: head.last_irreversible_block }, nonce: '0', mana: mana.toString(), balance } };
  await reviewDeploy(pkg); return pkg;
}
export async function signDeploy(pkg: DeployPackage, signer: Signer, expectedId: string): Promise<DeployPackage> {
  const review = await reviewDeploy(pkg); requireValue(expectedId === review.id, 'Confirm the exact reviewed bootstrap ID.');
  requireValue(signer.getAddress() === review.treasury && !review.signed, 'Only the unsigned bootstrap can be signed, by the treasury address key.');
  const next = structuredClone(pkg); next.transaction.signatures.push(utils.encodeBase64url(await signer.signHash(Buffer.from(review.id.slice(6), 'hex'))));
  requireValue(body(next) === body(pkg) && (await reviewDeploy(next)).signed, 'Signing changed the bootstrap.'); return next;
}
export async function submitDeploy(pkg: DeployPackage, provider: Provider, confirmedId: string, waitMs: number, dryRun: boolean): Promise<any> {
  const review = await reviewDeploy(pkg); requireValue(review.signed, 'The bootstrap is not signed.');
  const profile = validateNetwork(pkg.network);
  requireValue(await provider.getChainId() === pkg.network.chainId, 'RPC chain does not match the network profile.');
  await virgin(provider, profile, review.treasury, review.koin);
  requireValue(uint(review.rcLimit) <= BigInt(await provider.getAccountRc(review.treasury)), 'Treasury address Mana is insufficient for the upload.');
  if (dryRun) return { dryRun: true, ...review, preflight: 'passed', submitted: false };
  requireValue(confirmedId === review.id, 'Confirm the exact bootstrap ID for submission.');
  const sent = await sendOnce(provider, pkg.transaction, review.id, { kind: 'bootstrap', package: pkg });
  const end = Date.now() + waitMs; let found: any = { status: sent, id: review.id };
  for (;;) {
    try { found = await findIncluded({ profile }, provider, profile === 'mainnet' ? (provider as MultisigProvider).witness : undefined, review.id, pkg.transaction, bootstrapSignature(review.treasury)); } catch { return { status: 'submitted-unconfirmed', id: review.id }; }
    if (['irreversible', 'reverted'].includes(found.status) || Date.now() >= end) return { ...found, receipt: undefined, status: found.status === 'unknown' ? 'submitted-unconfirmed' : found.status, next: 'Run multisig verify-deployment before any funding.' };
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
}
/// Post-upload checklist. Produces the treasury manifest only when every check passes on an irreversible block.
export async function verifyDeployment(pkg: DeployPackage, provider: Provider, waitMs = 0): Promise<any> {
  const review = await reviewDeploy(pkg); requireValue(review.signed, 'Unsigned bootstrap package.');
  const profile = validateNetwork(pkg.network); const t = review.treasury;
  requireValue(await provider.getChainId() === pkg.network.chainId, 'RPC chain does not match the network profile.');
  const witness = profile === 'mainnet' ? (provider as MultisigProvider).witness : undefined;
  if (profile === 'mainnet') requireValue(witness?.readOnly, 'Mainnet verification requires the corroborating RPC.');
  const found = await findIncluded({ profile }, provider, witness, review.id, pkg.transaction, bootstrapSignature(t));
  if (found.status !== 'irreversible') return { status: found.status === 'included' ? 'included-not-irreversible' : found.status, id: review.id, message: 'Not verified. Do not fund.' };
  const checks = async (p: Provider) => {
    const { codeSha256, meta } = await deployedCode(p, t); const template = await readMethod(p, t, TREASURY_ABI, 'get_template');
    return { codeSha256, metaHash: meta?.hash, flags: meta && { call: !!meta.call, transaction: !!meta.transaction, upload: !!meta.upload, system: !!meta.system },
      policySpaceEmpty: await policySpaceEmpty(p, t), policy: await readPolicy(p, t), nonce: (await nonceOf(p, t)).toString(), allowances: await allowanceCount(p, review.koin, t), fundVotes: await fundVotes(p, profile, t),
      template: { name: template.name, version: template.version, chainId: template.chain_id, koin: template.koin_contract, min: template.min_owners, max: template.max_owners } };
  };
  // The whole checklist is read at ONE block (same head before and after; retried a few times) on each RPC, and
  // that observation block must itself be canonical and irreversible: state seen only at a reversible head (e.g. a
  // pre-upload allowance exhausted in a block that can still be reorganized away) proves nothing permanent.
  const atOneBlock = async (p: Provider) => {
    for (let attempt = 0; attempt < 5; attempt++) {
      const before = await p.getHeadInfo(); const value = await checks(p); const after = await p.getHeadInfo();
      if (before.head_topology.id === after.head_topology.id && before.head_state_merkle_root === after.head_state_merkle_root) return { value, head: after };
    }
    throw new RefusalError('The chain head kept moving during verification; retry.');
  };
  const first = await atOneBlock(provider); const v = first.value; const anchors = [first.head.head_topology];
  if (witness) {
    const second = await atOneBlock(witness); requireValue(canonical(v) === canonical(second.value), 'Independent RPCs disagree on the deployment.');
    await corroborate(provider, witness, first.head, second.head, uint(found.height)); anchors.push(second.head.head_topology);
  }
  // Every observation block (primary AND witness) must become irreversible and stay canonical on every RPC.
  const anchor = anchors.reduce((a, b) => (uint(b.height) > uint(a.height) ? b : a));
  // Wait (bounded) until the observation block is irreversible on every RPC; on a live chain this takes about
  // one irreversibility window (Mainnet: ~60 blocks, ~3 minutes).
  const end = Date.now() + waitMs;
  for (const p of [provider, witness].filter(Boolean) as Provider[]) {
    let final = await p.getHeadInfo();
    while (uint(final.last_irreversible_block) < uint(anchor.height) && Date.now() < end) { await new Promise(r => setTimeout(r, 3000)); final = await p.getHeadInfo(); }
    requireValue((await canonicalBlock(p, final, uint(found.height))).block_id === found.block && uint(final.last_irreversible_block) >= uint(found.height), 'Bootstrap block finality changed during verification.');
    if (uint(final.last_irreversible_block) < uint(anchor.height)) return { status: 'observation-not-irreversible', id: review.id, observedAt: anchors.map(a => a.height), lib: final.last_irreversible_block, message: 'Checks passed at a block that is not yet irreversible. Run verify-deployment again later; nothing was written.' };
    for (const a of anchors) requireValue((await canonicalBlock(p, final, uint(a.height))).block_id === a.id, 'An observation block is no longer canonical; run verify-deployment again.');
  }
  const failures: string[] = [];
  if (v.codeSha256 !== review.wasmSha256 || v.metaHash !== utils.encodeBase64url(Buffer.from('1220' + review.wasmSha256, 'hex'))) failures.push('code or metadata hash differs');
  if (!v.flags || !v.flags.call || !v.flags.transaction || !v.flags.upload || v.flags.system) failures.push('authority flags are not exactly call+transaction+upload');
  if (!v.policySpaceEmpty) failures.push('policy storage is not empty (seeded storage)');
  if (canonical(v.policy) !== canonical({ owners: review.owners, threshold: review.threshold, version: '0' })) failures.push('policy is not the embedded initial policy v0');
  if (v.nonce !== '1') failures.push('treasury nonce is not 1 (the address paid for other transactions)');
  if (v.allowances !== 0) failures.push('KOIN allowances exist (pre-upload approve)');
  if (v.fundVotes) failures.push('Koinos Fund votes exist');
  const fundCheck = v.fundVotes === null ? 'not checked: no Fund contract is bound to this network profile' : 'no votes';
  if (v.template.name !== TEMPLATE_NAME || v.template.version !== TEMPLATE_VERSION || v.template.koin !== review.koin || v.template.min !== MIN_OWNERS || v.template.max !== MAX_OWNERS
    || v.template.chainId !== pkg.network.chainId) failures.push('template bindings differ');
  if (failures.length) return { status: 'refused', id: review.id, failures, message: 'Deployment is NOT safe to fund. Do not publish or fund this address.' };
  const manifest = { schema: 1, kind: 'kcli-multisig-treasury', network: pkg.network, token: { symbol: 'KOIN', contract: review.koin, decimals: 8 },
    treasury: { address: t, template: TEMPLATE_NAME, templateVersion: TEMPLATE_VERSION, codeSha256: review.wasmSha256, abiSha256: review.abiSha256, sourceSha256: review.sourceSha256, inputsSha256: pkg.artifact.inputsSha256, bootstrap: { transactionId: review.id, blockId: found.block, height: found.height } },
    policy: { owners: review.owners, threshold: review.threshold, version: '0' } };
  validateManifest(manifest);
  // 'deployment-verified' covers everything readable on chain. It is not a qualification: an independent reviewer
  // still reproduces the build, repeats the negative-authority checks with another client and (Mainnet) attests
  // the manifest; without that attestation Mainnet members cannot sign at all.
  return { status: 'deployment-verified', id: review.id, block: found.block, height: found.height, checks: { ...v, fundCheck }, manifest,
    remaining: ['Independent reviewer: reproduce wasmSha256 from source + inputs, and prove with another client that the address key alone cannot transfer, pay Mana, set_policy or upload.', profile === 'mainnet' ? 'Mainnet: member signing stays blocked until the manifest carries an independent Ed25519 attestation.' : 'Distribute the manifest fingerprint through an independent channel.', 'Funding needs separate authorization; start with a small amount.'] };
}
export const writeManifest = (file: string, manifest: any): string => { writeExclusive(file, manifest); return sha(readSafe(file)); };
