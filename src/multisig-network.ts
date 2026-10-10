import { createPublicKey, randomInt, verify } from 'crypto';
import * as http from 'http';
import * as https from 'https';
import { Provider, utils } from 'koilib';
import { objectKeys, readSafe, RefusalError, requireValue, strictJson } from './secure-files';
import { b64, sha, uint } from './vortex-protocol';
import { canonicalBlock, MAINNET_CHAIN, rpcUrl, TESTNET_CHAINS } from './vortex-network';

export type MultisigProfile = 'local' | 'testnet' | 'mainnet';
export const PROFILES: MultisigProfile[] = ['local', 'testnet', 'mainnet'];
// Pinned KOIN contracts of the public profiles (local profiles carry their own in the manifest).
export const PUBLIC_KOIN: Record<string, string> = { mainnet: '19GYjDBVXU7keLbYvMLazsGQn3GTWHjHkK', testnet: '1FaSvLjQJsCJKq5ybmGsMMQs8RQYyVv8ju' };
// Fund contract whose votes the bootstrap checklist reads. Profiles without one report the check as not performed.
export const PUBLIC_FUND: Record<string, string> = { mainnet: '1A5BmMqV5jN5zBrdkhQumAfDZBzXLPBeN9' };

export function validateNetwork(network: any): MultisigProfile {
  requireValue(network && PROFILES.includes(network.name), 'Unsupported network profile.');
  b64(network.chainId, 34);
  if (network.name === 'mainnet') {
    objectKeys(network, ['name', 'chainId', 'rpcs']); requireValue(network.chainId === MAINNET_CHAIN, 'Not the Mainnet chain ID.');
    requireValue(Array.isArray(network.rpcs) && network.rpcs.length === 2, 'Mainnet requires two independently operated reviewed RPCs.');
    const hosts: string[] = [], operators: string[] = [];
    for (const rpc of network.rpcs) {
      objectKeys(rpc, ['url', 'operator']); rpcUrl(rpc.url, 'mainnet'); hosts.push(new URL(rpc.url).hostname);
      requireValue(typeof rpc.operator === 'string' && /^[a-z0-9][a-z0-9.-]{1,63}$/.test(rpc.operator), 'Invalid reviewed RPC operator identity.'); operators.push(rpc.operator);
    }
    requireValue(new Set(hosts).size === 2 && new Set(operators).size === 2, 'RPC hosts and operators must be independent.');
  } else {
    objectKeys(network, ['name', 'chainId']);
    if (network.name === 'testnet') requireValue(TESTNET_CHAINS.includes(network.chainId), 'Not a known official testnet chain ID (refresh the manifest after a testnet reset).');
    else requireValue(network.chainId !== MAINNET_CHAIN && !TESTNET_CHAINS.includes(network.chainId), 'Local profiles cannot use a public chain ID.');
  }
  return network.name;
}
export function checkRpc(url: string, profile: MultisigProfile): string {
  requireValue(typeof url === 'string' && url.length <= 512, 'Invalid RPC URL.');
  rpcUrl(url, profile === 'local' ? 'local' : 'mainnet');
  return url;
}
export const redact = (url: string): string => { try { const u = new URL(url); return u.origin; } catch { return '[invalid url]'; } };

/// Mainnet manifests need an Ed25519 attestation by an independently trusted review key. The domain tag keeps
/// Vortex and multisig attestations apart. The review key attests provenance only; it never controls funds.
export function authenticateReview(text: string, file: string | undefined, fingerprint: string | undefined, purpose: 'manifest' | 'bootstrap'): void {
  requireValue(file && fingerprint && /^[a-f0-9]{64}$/.test(fingerprint), 'Mainnet requires --review and an independently trusted --review-key SHA-256 fingerprint.');
  const attestation = strictJson(readSafe(file));
  objectKeys(attestation, ['schema', 'kind', 'manifestSha256', 'publicKey', 'signature']);
  requireValue(attestation.schema === 1 && attestation.kind === `kcli-multisig-${purpose}-review` && attestation.manifestSha256 === sha(text), `Review attestation does not bind this exact ${purpose}.`);
  const der = b64(attestation.publicKey, 44);
  requireValue(sha(der) === fingerprint, 'Review key does not match the explicitly trusted fingerprint.');
  const key = createPublicKey({ key: der, format: 'der', type: 'spki' });
  requireValue(key.asymmetricKeyType === 'ed25519' && verify(null, Buffer.from(`kcli-multisig-${purpose}-v1\n` + attestation.manifestSha256), key, b64(attestation.signature, 64)), 'Invalid Ed25519 manifest review signature.');
}

/// Bounded read window for multisig state. Kernel writes are matched in the KERNEL
/// zone: KOIN is a system contract that keeps balances in a system space with id 1 under its own zone, written in
/// practically every block (Mana), which is not a system-call dispatch change. Protected inside a window:
/// - kernel: system-call dispatch (1), bytecode/metadata (2/3) of the treasury and of KOIN, the treasury nonce (4);
/// - system-contract storage (any non-kernel zone, e.g. KOIN balances/allowances) whose key starts with the
///   treasury address -- KOIN's storage zone is not its contract ID, so the treasury key is what identifies it;
/// - the treasury's own contract storage.
export function protectedDelta(delta: any, treasury: string, koin: string): boolean {
  const space = delta.object_space;
  requireValue(space && typeof space === 'object' && Number.isInteger(space.id ?? 0) && (space.id ?? 0) >= 0 && typeof (space.system ?? false) === 'boolean', 'Invalid state-delta object space.');
  const key = b64(delta.key ?? '', undefined, 900000); const objectZone = space.zone ?? ''; b64(objectZone); const id = space.id ?? 0;
  const t = Buffer.from(utils.decodeBase58(treasury)), k = Buffer.from(utils.decodeBase58(koin));
  if (space.system && objectZone === '') return id === 1 || ([2, 3].includes(id) && (key.equals(t) || key.equals(k))) || (id === 4 && key.equals(t));
  if (space.system) return key.length >= t.length && key.subarray(0, t.length).equals(t);
  return objectZone === utils.encodeBase64url(t);
}
function headValid(h: any, strictTime: boolean): void {
  requireValue(/^0x1220[0-9a-f]{64}$/.test(h.head_topology?.id), 'Invalid canonical head.');
  uint(h.head_topology.height); uint(h.head_block_time);
  requireValue(uint(h.last_irreversible_block) <= uint(h.head_topology.height), 'Invalid irreversible height.');
  requireValue(typeof h.head_state_merkle_root === 'string' && h.head_state_merkle_root.length > 0, 'Missing state read anchor.');
  if (strictTime) {
    requireValue(b64(h.head_state_merkle_root, 34).subarray(0, 2).equals(Buffer.from([0x12, 0x20])), 'Invalid state-root multihash.');
    requireValue(Math.abs(Date.now() - Number(uint(h.head_block_time))) <= 120000, 'RPC head is stale or ahead of the trusted local clock.');
  }
}
export async function treasuryUnchanged(provider: Provider, treasury: string, koin: string, before: any, after: any): Promise<void> {
  const first = uint(before.head_topology.height), last = uint(after.head_topology.height);
  requireValue(last >= first && last - first <= 16n && uint(after.last_irreversible_block) >= uint(before.last_irreversible_block), 'Read interval regressed or exceeded the verification bound.');
  if (before.head_topology.id === after.head_topology.id) {
    requireValue(first === last && before.head_state_merkle_root === after.head_state_merkle_root && before.head_block_time === after.head_block_time, 'State changed under the same read anchor.');
    return;
  }
  requireValue(last > first, 'Head forked during state reads; retry.');
  let previous = (await canonicalBlock(provider, after, first)).block_id;
  requireValue(previous === before.head_topology.id, 'Read anchor is no longer canonical.');
  for (let height = first + 1n; height <= last; height++) {
    const item = await canonicalBlock(provider, after, height, true);
    requireValue(item.block?.id === item.block_id && item.block.header?.height === height.toString() && item.block.header.previous === previous && item.receipt?.id === item.block_id && item.receipt.height === height.toString(), 'Canonical receipt chain is missing or inconsistent.');
    const entries = item.receipt.state_delta_entries ?? []; requireValue(Array.isArray(entries), 'Invalid canonical state deltas.');
    for (const delta of entries) requireValue(!protectedDelta(delta, treasury, koin), 'Treasury code, nonce, storage, KOIN balance/allowances, KOIN code or system-call dispatch changed during reads; retry.');
    previous = item.block_id;
  }
  requireValue(previous === after.head_topology.id, 'Read interval does not reach the reported head.');
}
export async function stableTreasuryRead<T>(provider: Provider, treasury: string, koin: string, strictTime: boolean, read: () => Promise<T>): Promise<{ value: T; before: any; head: any }> {
  const before = await provider.getHeadInfo(); headValid(before, strictTime);
  const value = await read(); const after = await provider.getHeadInfo(); headValid(after, strictTime);
  await treasuryUnchanged(provider, treasury, koin, before, after);
  return { value, before, head: after };
}

const READS = new Set(['chain.get_chain_id', 'chain.get_head_info', 'chain.invoke_system_call', 'chain.read_contract', 'chain.get_account_nonce', 'chain.get_account_rc', 'transaction_store.get_transactions_by_id', 'block_store.get_blocks_by_id', 'block_store.get_blocks_by_height']);
export const TRANSPORT = { maxSockets: 2, requestTimeoutMs: 10000, readRetries: 2, maxResponseBytes: 1024 * 1024 };

/// Transport scoped to multisig commands (no global koilib/fetch behaviour change): at most two sockets and two
/// active requests per endpoint, a 10 s request timeout bounded by one command deadline, at most two retries for
/// reads only (submission is never retried), bounded responses, redacted errors, agent closed by close().
export class MultisigProvider extends Provider {
  witness?: MultisigProvider;
  readonly stats = { sockets: 0, requests: 0, retries: 0, maxActive: 0 };
  private active = 0; private waiting: (() => void)[] = []; private closed = false;
  private readonly agent: http.Agent;
  constructor(readonly rpc: string, readonly profile: MultisigProfile, readonly deadline: number, readonly readOnly = false) {
    super(checkRpc(rpc, profile));
    requireValue(profile === 'local' || process.env.NODE_TLS_REJECT_UNAUTHORIZED !== '0', 'Public profiles require TLS certificate verification.');
    const Agent = new URL(rpc).protocol === 'https:' ? https.Agent : http.Agent;
    this.agent = new Agent({ keepAlive: true, maxSockets: TRANSPORT.maxSockets, maxFreeSockets: TRANSPORT.maxSockets, timeout: TRANSPORT.requestTimeoutMs });
    const create = (this.agent as any).createConnection.bind(this.agent);
    (this.agent as any).createConnection = (...args: any[]) => { this.stats.sockets++; return create(...args); };
  }
  close(): void { this.closed = true; this.agent.destroy(); this.witness?.close(); }
  private async slot(): Promise<void> {
    if (this.active < TRANSPORT.maxSockets) { this.active++; this.stats.maxActive = Math.max(this.stats.maxActive, this.active); return; }
    // Queue wait is bounded by the command deadline too.
    await new Promise<void>((resolve, reject) => {
      const entry = () => { clearTimeout(timer); resolve(); };
      const timer = setTimeout(() => { this.waiting = this.waiting.filter(w => w !== entry); reject(new RefusalError('Command deadline reached while waiting for an RPC slot.')); }, Math.max(0, this.deadline - Date.now()));
      this.waiting.push(entry);
    });
    this.active++; this.stats.maxActive = Math.max(this.stats.maxActive, this.active);
  }
  private release(): void { this.active--; this.waiting.shift()?.(); }
  private once(method: string, params: any): Promise<any> {
    const remaining = this.deadline - Date.now();
    requireValue(remaining > 0 && !this.closed, 'Command deadline reached; outcome of reads is unknown.');
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }); const url = new URL(this.rpc);
    const lib = url.protocol === 'https:' ? https : http;
    return new Promise((resolve, reject) => {
      const req = lib.request(url, { method: 'POST', agent: this.agent, headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) }, timeout: Math.min(TRANSPORT.requestTimeoutMs, remaining) }, res => {
        const chunks: Buffer[] = []; let size = 0;
        res.on('data', (c: Buffer) => { size += c.length; if (size > TRANSPORT.maxResponseBytes) { req.destroy(); reject(Object.assign(new Error('oversized'), { retry: false })); } else chunks.push(c); });
        res.on('end', () => {
          const status = res.statusCode || 0;
          if (status === 429 || status >= 500) return reject(Object.assign(new Error('unavailable'), { retry: true }));
          if (status !== 200) return reject(Object.assign(new Error('refused'), { retry: false }));
          try { resolve(strictJson(Buffer.concat(chunks).toString('utf8'))); } catch { reject(Object.assign(new Error('invalid'), { retry: false })); }
        });
        res.on('error', () => reject(Object.assign(new Error('reset'), { retry: true })));
      });
      req.on('timeout', () => { req.destroy(); reject(Object.assign(new Error('timeout'), { retry: true })); });
      // Wall-clock bound for the whole request (a trickling server cannot extend it).
      const wall = setTimeout(() => { req.destroy(); reject(Object.assign(new Error('wall-clock timeout'), { retry: true })); }, Math.min(TRANSPORT.requestTimeoutMs, remaining));
      req.on('close', () => clearTimeout(wall));
      req.on('error', () => reject(Object.assign(new Error('transport'), { retry: true })));
      req.end(body);
    });
  }
  async call<T = any>(method: string, params: any): Promise<T> {
    const write = method === 'chain.submit_transaction';
    requireValue(READS.has(method) || write, 'Unsupported multisig RPC method.');
    requireValue(!write || !this.readOnly, 'Corroborating RPC is read-only.');
    await this.slot();
    try {
      for (let attempt = 0; ; attempt++) {
        this.stats.requests++;
        try {
          const result = await this.once(method, params);
          requireValue(result && result.id === 1 && result.jsonrpc === '2.0' && Object.prototype.hasOwnProperty.call(result, 'result') && !result.error, 'RPC refused the request or returned an invalid response.');
          return result.result;
        } catch (error: any) {
          if (error instanceof RefusalError) throw error;
          // Never resend a write: a timeout after sending means unknown outcome, not failure.
          if (write || !error.retry || attempt >= TRANSPORT.readRetries) throw new RefusalError(`RPC ${redact(this.rpc)} request failed (response details withheld).`);
          this.stats.retries++;
          const wait = Math.min(250 * 2 ** attempt + randomInt(0, 200), Math.max(0, this.deadline - Date.now() - 100));
          await new Promise(resolve => setTimeout(resolve, wait));
        }
      }
    } finally { this.release(); }
  }
}
export function multisigProvider(network: any, rpc: string, deadline: number, corroboratingRpc?: string): MultisigProvider {
  const profile = validateNetwork(network);
  const provider = new MultisigProvider(rpc, profile, deadline);
  if (profile === 'mainnet') {
    const urls = network.rpcs.map((r: any) => r.url);
    requireValue(corroboratingRpc && rpc !== corroboratingRpc && urls.includes(rpc) && urls.includes(corroboratingRpc), 'Explicit primary and corroborating RPCs must match the authenticated manifest.');
    provider.witness = new MultisigProvider(corroboratingRpc, profile, deadline, true);
  } else requireValue(!corroboratingRpc, 'Only Mainnet profiles use a corroborating RPC.');
  return provider;
}
