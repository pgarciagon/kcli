import { Contract, utils } from 'koilib';
import tokenAbi from './abis/token.json';
import fogataAbi from './abis/fogata.json';
import { DashboardProvider, DashboardReadCache, ReadSnapshot, ReadSpec } from './dashboard-rpc';

export function dashboardAge(ageMs: number): string {
  const seconds = Math.floor(Math.max(0, ageMs) / 1000);
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m${seconds % 60}s`;
  return `${Math.floor(seconds / 3600)}h${Math.floor(seconds % 3600 / 60)}m`;
}

export function dashboardValue<T>(snapshot: ReadSnapshot<T>, format: (value: T) => string, width = 24): string {
  if (snapshot.value === undefined) return 'n/a';
  const suffix = snapshot.stale ? ` stale:${dashboardAge(snapshot.ageMs ?? 0)}` : '';
  const value = format(snapshot.value);
  const available = Math.max(1, width - suffix.length);
  return `${value.length > available ? `${value.slice(0, Math.max(0, available - 3))}...` : value}${suffix}`;
}

export function dashboardWholeUnits(value: bigint): string {
  return (value / 100000000n).toLocaleString('en-US');
}

export interface PoolInfo { name: string }

export class DashboardProducerData {
  readonly cache: DashboardReadCache;
  private readonly koin: Contract;
  private readonly vhp: Contract;
  constructor(readonly provider: DashboardProvider, network: string, readonly koinId: string, readonly vhpId: string,
    readonly balanceTtlMs = 30000, readonly poolTtlMs = 600000, now: () => number = Date.now, staggerMs = 150, concurrency = 2) {
    this.cache = new DashboardReadCache(network, provider.rpcNodes[0], concurrency, staggerMs, now);
    // A successfully returned empty protobuf uint64 message represents zero. Missing RPC results never do.
    const abi = { ...tokenAbi, methods: { ...tokenAbi.methods,
      balance_of: { ...tokenAbi.methods.balance_of, default_output: { value: '0' } },
      total_supply: { ...tokenAbi.methods.total_supply, default_output: { value: '0' } } } };
    this.koin = new Contract({ id: koinId, abi, provider });
    this.vhp = new Contract({ id: vhpId, abi, provider });
  }

  balanceSpec(token: 'koin' | 'vhp', owner: string): ReadSpec<bigint> {
    const contract = token === 'koin' ? this.koin : this.vhp;
    return { contract: contract.getId(), method: 'balance_of', args: { owner }, ttlMs: this.balanceTtlMs,
      read: async () => this.amount((await contract.functions.balance_of({ owner })).result) };
  }

  supplySpec(token: 'koin' | 'vhp'): ReadSpec<bigint> {
    const contract = token === 'koin' ? this.koin : this.vhp;
    return { contract: contract.getId(), method: 'total_supply', args: {}, ttlMs: this.balanceTtlMs,
      read: async () => this.amount((await contract.functions.total_supply({})).result) };
  }

  poolSpec(owner: string): ReadSpec<PoolInfo> {
    return { contract: owner, method: 'get_pool_params', args: {}, ttlMs: this.poolTtlMs, read: async () => {
      const contract = new Contract({ id: owner, abi: fogataAbi, provider: this.provider });
      const { result } = await contract.functions.get_pool_params({});
      if (!result || typeof result !== 'object' || typeof result.name !== 'string') throw new Error('Invalid pool result');
      // Contract-supplied names must not inject terminal control sequences.
      return { name: result.name.replace(/[\x00-\x1f\x7f-\x9f]/g, '').trim().slice(0, 100) || 'Fogata Pool' };
    } };
  }

  select(producers: string[], visible: string[]): void {
    const specs: ReadSpec[] = [];
    for (const owner of visible) specs.push(this.balanceSpec('koin', owner), this.balanceSpec('vhp', owner));
    for (const owner of producers) {
      if (!visible.includes(owner)) specs.push(this.balanceSpec('vhp', owner));
    }
    specs.push(this.supplySpec('koin'), this.supplySpec('vhp'));
    for (const owner of visible) specs.push(this.poolSpec(owner));
    this.cache.setWanted(specs);
  }

  balance(token: 'koin' | 'vhp', owner: string): ReadSnapshot<bigint> { return this.cache.peek(this.balanceSpec(token, owner)); }
  supply(token: 'koin' | 'vhp'): ReadSnapshot<bigint> { return this.cache.peek(this.supplySpec(token)); }
  pool(owner: string): ReadSnapshot<PoolInfo> { return this.cache.peek(this.poolSpec(owner)); }

  apy(producers: string[]): ReadSnapshot<string> {
    const inputs = [this.supply('koin'), this.supply('vhp'), ...producers.map(owner => this.balance('vhp', owner))];
    if (!producers.length || inputs.some(input => input.value === undefined)) return { stale: false, loading: inputs.some(input => input.loading) };
    const active = inputs.slice(2).reduce((sum, input) => sum + input.value!, 0n);
    if (active === 0n) return { stale: false, loading: false };
    const virtual = inputs[0].value! + inputs[1].value!;
    const value = (2 * Number(utils.formatUnits(virtual.toString(), 8)) / Number(utils.formatUnits(active.toString(), 8))).toFixed(2);
    return { value, stale: inputs.some(input => input.stale), ageMs: Math.max(...inputs.map(input => input.ageMs ?? 0)),
      updatedAt: Math.min(...inputs.map(input => input.updatedAt!)), loading: inputs.some(input => input.loading) };
  }

  warnings(producers: string[], visible: string[]): string[] {
    const reads = [this.supply('koin'), this.supply('vhp'), ...producers.map(owner => this.balance('vhp', owner)),
      ...visible.flatMap(owner => [this.balance('koin', owner), this.pool(owner)])];
    const counts = new Map<string, number>();
    for (const read of reads) if (read.error) counts.set(read.error, (counts.get(read.error) ?? 0) + 1);
    return [...counts].slice(0, 3).map(([error, count]) => `${error} (${count} data item${count === 1 ? '' : 's'})`);
  }

  private amount(result: unknown): bigint {
    const value = (result as { value?: unknown } | undefined)?.value;
    if (typeof value !== 'string' || !/^\d+$/.test(value)) throw new Error('Invalid token amount');
    return BigInt(value);
  }
}
