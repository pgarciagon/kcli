import { createPublicKey, verify } from 'crypto';
import { Provider, utils } from 'koilib';
import { canonical, objectKeys, readSafe, requireValue, strictJson } from './secure-files';
import { b64, sha, uint } from './vortex-protocol';

export const MAINNET_CHAIN = 'EiBZK_GGVP0H_fXVAM3j6EAuz3-B-l3ejxRSewi7qIBfSA==';
export const TESTNET_CHAINS = ['EiAIKVvm6-V2qmsmUvPJy09vCCLbtn9lHFpwrJbcTIEWRQ==', 'EiBncD4pKRIQWco_WRqo5Q-xnXR7JuO3PtZv983mKdKHSQ=='];
export type NetworkProfile = 'local' | 'mainnet';

export function rpcUrl(value: string, profile: NetworkProfile): string {
  const u = new URL(value);
  requireValue(!u.username && !u.password && !u.hash && !u.search, 'RPC credentials, query strings and fragments are not supported.');
  if (profile === 'local') requireValue(u.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(u.hostname), 'Use an explicit loopback HTTP RPC for the local profile.');
  else requireValue(u.protocol === 'https:' && /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(u.hostname) && !/\.(local|localhost|internal|test|invalid|example)$/.test(u.hostname), 'Mainnet RPC requires HTTPS and a public hostname.');
  if (profile === 'mainnet') requireValue(value === u.href, 'Use a canonical RPC URL, including its trailing slash.');
  return u.origin;
}

export function validateNetwork(schema: number, network: any): void {
  if (network.name === 'local') {
    objectKeys(network, ['name', 'chainId']);
    requireValue(schema === 1 && ![MAINNET_CHAIN, ...TESTNET_CHAINS].includes(network.chainId), 'Local profiles cannot use a public chain ID.');
  } else {
    objectKeys(network, ['name', 'chainId', 'rpcs']);
    requireValue(schema === 2 && network.name === 'mainnet' && network.chainId === MAINNET_CHAIN, 'Unsupported public network profile.');
    requireValue(Array.isArray(network.rpcs) && network.rpcs.length === 2, 'Mainnet requires two independently operated reviewed RPCs.');
    const origins: string[] = [], hosts: string[] = [], operators: string[] = [];
    for (const rpc of network.rpcs) {
      objectKeys(rpc, ['url', 'operator']); origins.push(rpcUrl(rpc.url, 'mainnet')); hosts.push(new URL(rpc.url).hostname);
      requireValue(typeof rpc.operator === 'string' && /^[a-z0-9][a-z0-9.-]{1,63}$/.test(rpc.operator), 'Invalid reviewed RPC operator identity.'); operators.push(rpc.operator);
    }
    requireValue(new Set(origins).size === 2 && new Set(hosts).size === 2 && new Set(operators).size === 2, 'RPC hosts, origins and reviewed operator identities must be independent.');
  }
  b64(network.chainId, 34);
}

export function authenticateReview(manifestText: string, file?: string, fingerprint?: string): void {
  requireValue(file && fingerprint && /^[a-f0-9]{64}$/.test(fingerprint), 'Mainnet requires --review and an independently trusted --review-key SHA-256 fingerprint.');
  const attestation = strictJson(readSafe(file));
  objectKeys(attestation, ['schema', 'manifestSha256', 'publicKey', 'signature']);
  requireValue(attestation.schema === 1 && attestation.manifestSha256 === sha(manifestText), 'Review attestation does not bind this exact manifest.');
  const der = b64(attestation.publicKey, 44);
  requireValue(sha(der) === fingerprint, 'Review key does not match the explicitly trusted fingerprint.');
  const key = createPublicKey({ key: der, format: 'der', type: 'spki' });
  requireValue(key.asymmetricKeyType === 'ed25519' && verify(null, Buffer.from('kcli-vortex-manifest-v2\n' + attestation.manifestSha256), key, b64(attestation.signature, 64)), 'Invalid Ed25519 manifest review signature.');
}

function headValid(h: any, mainnet: boolean): void {
  requireValue(/^0x1220[0-9a-f]{64}$/.test(h.head_topology?.id), 'Invalid canonical head.');
  uint(h.head_topology.height); uint(h.head_block_time);
  requireValue(uint(h.last_irreversible_block) <= uint(h.head_topology.height), 'Invalid irreversible height.');
  requireValue(typeof h.head_state_merkle_root === 'string' && h.head_state_merkle_root.length > 0, 'Missing state read anchor.');
  if (mainnet) {
    requireValue(b64(h.head_state_merkle_root, 34).subarray(0, 2).equals(Buffer.from([0x12, 0x20])), 'Invalid mainnet state-root multihash.');
    requireValue(Math.abs(Date.now() - Number(uint(h.head_block_time))) <= 120000, 'Mainnet RPC head is stale or ahead of the trusted local clock.');
  }
}

export async function canonicalBlock(provider: Provider, head: any, height: bigint, full = false): Promise<any> {
  requireValue(height > 0n && height <= uint(head.head_topology.height) && height <= BigInt(Number.MAX_SAFE_INTEGER), 'Unsupported canonical height.');
  const items = await provider.getBlocks(Number(height), 1, head.head_topology.id, { returnBlock: full, returnReceipt: full });
  const item = items[0];
  requireValue(items.length === 1 && item?.block_height === height.toString() && /^0x1220[0-9a-f]{64}$/.test(item.block_id), 'Canonical block verification unavailable.');
  return item;
}

// Head-only RPC reads are optimistic, not historical reads. Canonical receipt
// deltas check that the protected bridge/code spaces did not change in-flight.
// RPC correctness remains a reviewed trust assumption, corroborated separately.
export async function unchangedInterval(provider: Provider, contract: string, before: any, after: any, monotonicLib = true, payer?: string): Promise<void> {
  const first = uint(before.head_topology.height), last = uint(after.head_topology.height);
  requireValue(last >= first && last - first <= 16n && (!monotonicLib || uint(after.last_irreversible_block) >= uint(before.last_irreversible_block)), 'Read interval regressed or exceeded the verification bound.');
  if (before.head_topology.id === after.head_topology.id) {
    requireValue(first === last && before.head_state_merkle_root === after.head_state_merkle_root && before.head_block_time === after.head_block_time, 'State changed under the same read anchor.');
  } else {
    requireValue(last > first, 'Head forked during state reads; recheck explicitly.');
    let previous = (await canonicalBlock(provider, after, first)).block_id;
    requireValue(previous === before.head_topology.id, 'Read anchor is no longer canonical.');
    const zone = utils.encodeBase64url(utils.decodeBase58(contract));
    const payerKey = payer && utils.encodeBase64url(utils.decodeBase58(payer));
    for (let height = first + 1n; height <= last; height++) {
      const item = await canonicalBlock(provider, after, height, true);
      requireValue(item.block?.id === item.block_id && item.block.header?.height === height.toString() && item.block.header.previous === previous && item.receipt?.id === item.block_id && item.receipt.height === height.toString(), 'Canonical receipt chain is missing or inconsistent.');
      const entries = item.receipt.state_delta_entries ?? [];
      requireValue(Array.isArray(entries), 'Invalid canonical state deltas.');
      for (const delta of entries) {
        const space = delta.object_space;
        requireValue(space && typeof space === 'object' && Number.isInteger(space.id ?? 0) && (space.id ?? 0) >= 0 && (space.id ?? 0) <= 0xffffffff && typeof (space.system ?? false) === 'boolean', 'Invalid state-delta object space.');
        const key = delta.key ?? ''; b64(key); const objectZone = space.zone ?? ''; b64(objectZone);
        const protectedWrite = space.system ? space.id === 1 || ([2, 3].includes(space.id) && key === zone) || (space.id === 4 && key === payerKey) : objectZone === zone;
        requireValue(!protectedWrite, 'Protected bridge/code/nonce state changed during reads; recheck explicitly.');
      }
      previous = item.block_id;
    }
    requireValue(previous === after.head_topology.id, 'Read interval does not reach the reported head.');
  }
}

export async function stableRead<T>(provider: Provider, contract: string, mainnet: boolean, read: () => Promise<T>, payer?: string): Promise<{ value: T; before: any; head: any }> {
  const before = await provider.getHeadInfo(); headValid(before, mainnet);
  const value = await read(); const after = await provider.getHeadInfo(); headValid(after, mainnet);
  await unchangedInterval(provider, contract, before, after, true, payer);
  return { value, before, head: after };
}

export async function corroborate(primary: Provider, witness: Provider, a: any, b: any, minimum = 0n): Promise<void> {
  headValid(a, true); headValid(b, true);
  if (a.head_topology.id === b.head_topology.id) requireValue(a.head_topology.height === b.head_topology.height && a.head_block_time === b.head_block_time && a.head_state_merkle_root === b.head_state_merkle_root, 'Independent RPCs disagree on the same read anchor.');
  const height = uint(a.head_topology.height) < uint(b.head_topology.height) ? uint(a.head_topology.height) : uint(b.head_topology.height);
  requireValue(height >= minimum && (uint(a.head_topology.height) > uint(b.head_topology.height) ? uint(a.head_topology.height) - height : uint(b.head_topology.height) - height) <= 16n, 'RPC heads are too far apart.');
  const one = await canonicalBlock(primary, a, height), two = await canonicalBlock(witness, b, height);
  requireValue(one.block_id === two.block_id, 'Independent RPCs disagree on the canonical chain.');
  const lib = uint(a.last_irreversible_block) < uint(b.last_irreversible_block) ? uint(a.last_irreversible_block) : uint(b.last_irreversible_block);
  requireValue(lib >= minimum && lib > 0n, 'Independent irreversible finality is not established.');
  const finalOne = await canonicalBlock(primary, a, lib), finalTwo = await canonicalBlock(witness, b, lib);
  requireValue(finalOne.block_id === finalTwo.block_id, 'Independent RPCs disagree at the common irreversible height.');
}

export const sameObservedState = (a: any, b: any) => canonical(a) === canonical(b);
