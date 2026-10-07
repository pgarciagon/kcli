import { Provider } from 'koilib';
import * as http from 'http';
import * as https from 'https';
import { Socket } from 'net';

export class DashboardRpcError extends Error {
  constructor(message: string, readonly recoverable = false) { super(message); }
}

export function dashboardError(error: unknown): string {
  if (error instanceof DashboardRpcError) return error.message;
  return 'Invalid or unavailable contract data';
}

export function parseDashboardInteger(value: string, label: string, max: number): number {
  if (!/^[1-9]\d*$/.test(value) || !Number.isSafeInteger(Number(value)) || Number(value) > max) {
    throw new Error(`${label} must be an integer from 1 to ${max}.`);
  }
  return Number(value);
}

export function stableKey(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableKey).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.entries(value).sort(([a], [b]) => a.localeCompare(b))
      .map(([key, item]) => `${JSON.stringify(key)}:${stableKey(item)}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

export interface DashboardRpcOptions {
  concurrency?: number;
  timeoutMs?: number;
  retries?: number;
  backoffMs?: number;
  idleSocketMs?: number;
  maxQueue?: number;
}

// Only the dashboard uses this provider. Inherited koilib reads dispatch through call().
export class DashboardProvider extends Provider {
  private readonly endpoint: URL;
  private readonly agent: http.Agent | https.Agent;
  private readonly concurrency: number;
  private readonly timeoutMs: number;
  private readonly retries: number;
  private readonly backoffMs: number;
  private readonly maxQueue: number;
  private readonly idleTimers = new Map<Socket, NodeJS.Timeout>();
  private readonly pending = new Map<string, Promise<unknown>>();
  private readonly queue: Array<{ run: () => Promise<unknown>; resolve: (value: unknown) => void; reject: (error: unknown) => void }> = [];
  private readonly requests = new Set<http.ClientRequest>();
  private active = 0;
  private closed = false;
  private sequence = 0;
  readonly metrics = { attempts: 0, errors: 0, retries: 0, maxActive: 0, connections: 0, maxSockets: 0 };
  private sockets = 0;

  constructor(endpoint: string, options: DashboardRpcOptions = {}) {
    super([endpoint]);
    this.endpoint = new URL(endpoint);
    if (!['http:', 'https:'].includes(this.endpoint.protocol)) throw new Error('Dashboard RPC requires HTTP or HTTPS');
    if (this.endpoint.username || this.endpoint.password) throw new Error('Dashboard RPC URL must not contain credentials');
    this.concurrency = options.concurrency ?? 2;
    this.timeoutMs = options.timeoutMs ?? 10000;
    this.retries = options.retries ?? 2;
    this.backoffMs = options.backoffMs ?? 250;
    this.maxQueue = options.maxQueue ?? 8;
    const idleMs = options.idleSocketMs ?? 1000;
    for (const [name, value, minimum, maximum] of [
      ['concurrency', this.concurrency, 1, 4], ['timeout', this.timeoutMs, 1, 60000],
      ['retries', this.retries, 0, 3], ['backoff', this.backoffMs, 0, 5000],
      ['queue capacity', this.maxQueue, 1, 1024], ['idle socket timeout', idleMs, 1, 30000],
    ] as const) {
      if (!Number.isInteger(value) || value < minimum || value > maximum) throw new Error(`Invalid dashboard RPC ${name}`);
    }
    const agentOptions = { keepAlive: true, maxSockets: this.concurrency, maxTotalSockets: this.concurrency,
      maxFreeSockets: this.concurrency, scheduling: 'lifo' as const };
    this.agent = this.endpoint.protocol === 'https:' ? new https.Agent(agentOptions) : new http.Agent(agentOptions);
    this.agent.on('free', (socket: Socket) => {
      this.clearIdle(socket);
      if (!Object.values(this.agent.freeSockets).some(sockets => sockets?.includes(socket))) return;
      const timer = setTimeout(() => { this.idleTimers.delete(socket); socket.destroy(); }, idleMs);
      timer.unref();
      this.idleTimers.set(socket, timer);
    });
  }

  override call<T = unknown>(method: string, params: unknown): Promise<T> {
    if (!['chain.get_chain_id', 'chain.get_head_info', 'chain.read_contract', 'block_store.get_blocks_by_height'].includes(method)) {
      return Promise.reject(new DashboardRpcError('Dashboard transport only permits its read-only RPC methods'));
    }
    if (this.closed) return Promise.reject(new DashboardRpcError('Dashboard stopped'));
    const key = stableKey([this.endpoint.href, method, params]);
    const existing = this.pending.get(key);
    if (existing) return existing as Promise<T>;
    if (this.queue.length >= this.maxQueue) return Promise.reject(new DashboardRpcError('Dashboard read queue is full', true));
    const promise = new Promise<unknown>((resolve, reject) => {
      this.queue.push({ run: () => this.withRetries(method, params), resolve, reject });
    }).finally(() => this.pending.delete(key));
    this.pending.set(key, promise);
    this.drain();
    return promise as Promise<T>;
  }

  private drain(): void {
    while (!this.closed && this.active < this.concurrency && this.queue.length) {
      const job = this.queue.shift()!;
      this.active++;
      this.metrics.maxActive = Math.max(this.metrics.maxActive, this.active);
      void job.run().then(job.resolve, job.reject).finally(() => { this.active--; this.drain(); });
    }
  }

  private async withRetries(method: string, params: unknown): Promise<unknown> {
    for (let attempt = 0; ; attempt++) {
      if (this.closed) throw new DashboardRpcError('Dashboard stopped');
      try { return await this.request(method, params); }
      catch (error) {
        this.metrics.errors++;
        if (!(error instanceof DashboardRpcError) || !error.recoverable || attempt >= this.retries || this.closed) throw error;
        this.metrics.retries++;
        const delay = Math.min(5000, this.backoffMs * 2 ** attempt) * (1 + Math.random() * 0.2);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }

  private request(method: string, params: unknown): Promise<unknown> {
    this.metrics.attempts++;
    const id = ++this.sequence;
    const body = JSON.stringify({ jsonrpc: '2.0', id, method, params });
    return new Promise((resolve, reject) => {
      const transport = this.endpoint.protocol === 'https:' ? https : http;
      const request = transport.request(this.endpoint, { method: 'POST', agent: this.agent,
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } }, response => {
        const chunks: Buffer[] = [];
        let size = 0;
        response.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > 32 * 1024 * 1024) request.destroy(new DashboardRpcError('RPC response exceeds dashboard size limit'));
          else chunks.push(chunk);
        });
        response.on('error', () => request.destroy(new DashboardRpcError('RPC response interrupted', true)));
        response.on('end', () => {
          if (!response.complete) return request.destroy(new DashboardRpcError('RPC response interrupted', true));
          const status = response.statusCode ?? 0;
          if (status !== 200) {
            const sessionLimit = /session limit reached/i.test(Buffer.concat(chunks).toString('utf8'));
            reject(new DashboardRpcError(`HTTP ${status}${sessionLimit ? ': session limit reached' : ': RPC unavailable'}`,
              [408, 429, 500, 502, 503, 504].includes(status)));
            return;
          }
          try {
            const json = JSON.parse(Buffer.concat(chunks).toString('utf8'));
            if (json.id !== id || json.jsonrpc !== '2.0') throw new DashboardRpcError('Invalid RPC response identity');
            if (json.error) {
              const sessionLimit = /session limit reached/i.test(String(json.error.message));
              throw new DashboardRpcError(sessionLimit ? 'RPC session limit reached' : `RPC read failed (code ${Number(json.error.code) || 'unknown'})`, sessionLimit);
            }
            if (json.result === undefined) throw new DashboardRpcError('RPC returned no result');
            if (method === 'chain.read_contract' && typeof json.result?.result !== 'string') throw new DashboardRpcError('RPC returned no contract result');
            resolve(json.result);
          } catch (error) { reject(error instanceof DashboardRpcError ? error : new DashboardRpcError('Invalid RPC JSON response')); }
        });
      });
      this.requests.add(request);
      const timeout = setTimeout(() => request.destroy(new DashboardRpcError(`RPC timeout (${this.timeoutMs / 1000}s)`, true)), this.timeoutMs);
      request.on('socket', socket => {
        this.clearIdle(socket);
        if (!(socket as Socket & { dashboardCounted?: boolean }).dashboardCounted) {
          (socket as Socket & { dashboardCounted?: boolean }).dashboardCounted = true;
          this.metrics.connections++;
          this.sockets++;
          this.metrics.maxSockets = Math.max(this.metrics.maxSockets, this.sockets);
          socket.once('close', () => { this.sockets--; this.clearIdle(socket); });
        }
      });
      request.once('error', (error: NodeJS.ErrnoException) => {
        const recoverable = ['ECONNRESET', 'ECONNREFUSED', 'EPIPE', 'ETIMEDOUT', 'EAI_AGAIN'].includes(error.code || '');
        reject(error instanceof DashboardRpcError ? error : new DashboardRpcError(recoverable ? 'RPC connection unavailable' : 'RPC transport failed', recoverable));
      });
      request.once('close', () => { clearTimeout(timeout); this.requests.delete(request); });
      request.end(body);
    });
  }

  private clearIdle(socket: Socket): void {
    const timer = this.idleTimers.get(socket);
    if (timer) clearTimeout(timer);
    this.idleTimers.delete(socket);
  }

  close(): void {
    this.closed = true;
    for (const job of this.queue.splice(0)) job.reject(new DashboardRpcError('Dashboard stopped'));
    for (const timer of this.idleTimers.values()) clearTimeout(timer);
    this.idleTimers.clear();
    for (const request of this.requests) request.destroy(new DashboardRpcError('Dashboard stopped'));
    this.agent.destroy();
  }
}

export interface ReadSpec<T = unknown> {
  contract: string;
  method: string;
  args: unknown;
  ttlMs: number;
  read: () => Promise<T>;
}

export interface ReadSnapshot<T> {
  value?: T;
  updatedAt?: number;
  ageMs?: number;
  stale: boolean;
  error?: string;
  loading: boolean;
}

interface CacheEntry {
  spec: ReadSpec;
  value?: unknown;
  updatedAt?: number;
  error?: string;
  nextAt: number;
  failures: number;
  inFlight?: Promise<void>;
}

export class DashboardReadCache {
  private readonly entries = new Map<string, CacheEntry>();
  private wanted = new Set<string>();
  private nextLaunchAt = 0;
  private running = 0;
  private closed = false;
  constructor(readonly network: string, readonly endpoint: string, private readonly concurrency = 2,
    private readonly staggerMs = 150, private readonly now: () => number = Date.now, private readonly maxEntries = 4096) {}

  key(spec: Pick<ReadSpec, 'contract' | 'method' | 'args'>): string {
    return stableKey([this.network, new URL(this.endpoint).href, spec.contract, spec.method, spec.args]);
  }

  setWanted(specs: ReadSpec[]): void {
    const wanted = new Set(specs.map(spec => this.key(spec)));
    const needed = [...wanted].filter(key => !this.entries.has(key)).length;
    // Preserve in-flight reads and last-good data, but evict inactive history before admitting new work.
    for (const [key, entry] of this.entries) {
      if (this.entries.size <= Math.max(0, this.maxEntries - needed)) break;
      if (!wanted.has(key) && !entry.inFlight) this.entries.delete(key);
    }
    this.wanted = wanted;
    for (const spec of specs) {
      const key = this.key(spec);
      const entry = this.entries.get(key);
      if (entry) entry.spec = spec;
      else if (this.entries.size < this.maxEntries) this.entries.set(key, { spec, nextAt: this.now(), failures: 0 });
    }
  }

  peek<T>(spec: Pick<ReadSpec, 'contract' | 'method' | 'args'>): ReadSnapshot<T> {
    const entry = this.entries.get(this.key(spec));
    if (!entry) return { stale: false, loading: false, error: this.wanted.has(this.key(spec)) ? 'Dashboard cache capacity reached' : undefined };
    const ageMs = entry.updatedAt === undefined ? undefined : Math.max(0, this.now() - entry.updatedAt);
    return { value: entry.value as T | undefined, updatedAt: entry.updatedAt, ageMs,
      stale: entry.updatedAt !== undefined && (!!entry.error || ageMs! >= entry.spec.ttlMs),
      error: entry.error, loading: !!entry.inFlight };
  }

  tick(): void {
    if (this.closed || this.running >= this.concurrency || this.now() < this.nextLaunchAt) return;
    const due = [...this.entries].filter(([key, entry]) => this.wanted.has(key) && !entry.inFlight && entry.nextAt <= this.now())
      .sort(([, a], [, b]) => a.nextAt - b.nextAt)[0];
    if (!due) return;
    this.nextLaunchAt = this.now() + this.staggerMs;
    void this.refresh(due[0]);
  }

  refresh(key: string): Promise<void> {
    const entry = this.entries.get(key);
    if (!entry || this.closed) return Promise.resolve();
    if (entry.inFlight) return entry.inFlight;
    if (this.running >= this.concurrency) return Promise.resolve();
    this.running++;
    entry.inFlight = Promise.resolve().then(entry.spec.read).then(value => {
      entry.value = value;
      entry.updatedAt = this.now();
      entry.error = undefined;
      entry.failures = 0;
      entry.nextAt = this.now() + entry.spec.ttlMs;
    }).catch(error => {
      entry.error = dashboardError(error);
      entry.failures++;
      entry.nextAt = this.now() + (error instanceof DashboardRpcError && error.recoverable
        ? Math.min(entry.spec.ttlMs, 5000 * 2 ** Math.min(entry.failures - 1, 4)) : entry.spec.ttlMs);
    }).finally(() => { this.running--; entry.inFlight = undefined; });
    return entry.inFlight;
  }

  close(): void { this.closed = true; this.wanted.clear(); }
}
