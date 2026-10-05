import * as fs from 'fs';
import * as path from 'path';
import { randomBytes } from 'crypto';

export class RefusalError extends Error {}

export function requireValue(condition: unknown, message: string): asserts condition {
  if (!condition) throw new RefusalError(message);
}

export function objectKeys(value: any, required: string[], optional: string[] = []): void {
  requireValue(value && typeof value === 'object' && !Array.isArray(value), 'Expected an object.');
  requireValue(required.every(k => Object.prototype.hasOwnProperty.call(value, k)) && Object.keys(value).every(k => [...required, ...optional].includes(k)), 'Missing or unexplained fields.');
}

// JSON.parse alone accepts duplicate keys; review packages must have one interpretation.
export function strictJson(text: string): any {
  requireValue(Buffer.byteLength(text) <= 1024 * 1024, 'JSON exceeds the size limit.');
  let i = 0;
  const ws = () => { while (/[ \t\r\n]/.test(text[i] || '') && i < text.length) i++; };
  const string = (): string => {
    const start = i++;
    while (i < text.length) {
      const c = text[i++];
      if (c === '\\') { i++; continue; }
      if (c === '"') return JSON.parse(text.slice(start, i));
    }
    throw new RefusalError('Invalid JSON.');
  };
  const value = (depth: number): any => {
    requireValue(depth <= 24, 'JSON nesting exceeds the limit.'); ws();
    if (text[i] === '"') return string();
    if (text[i] === '{') {
      i++; ws(); const obj = Object.create(null); const seen = new Set<string>();
      if (text[i] === '}') { i++; return obj; }
      for (;;) {
        requireValue(text[i] === '"', 'Invalid JSON.'); const key = string();
        requireValue(!seen.has(key) && !['__proto__', 'constructor', 'prototype'].includes(key), 'Duplicate or unsafe JSON key.');
        seen.add(key); ws(); requireValue(text[i++] === ':', 'Invalid JSON.'); obj[key] = value(depth + 1); ws();
        const c = text[i++]; if (c === '}') return obj; requireValue(c === ',', 'Invalid JSON.'); ws();
      }
    }
    if (text[i] === '[') {
      i++; ws(); const array: any[] = []; if (text[i] === ']') { i++; return array; }
      for (;;) { array.push(value(depth + 1)); ws(); const c = text[i++]; if (c === ']') return array; requireValue(c === ',', 'Invalid JSON.'); }
    }
    const m = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(i));
    requireValue(m, 'Invalid JSON.'); i += m[0].length; const result = JSON.parse(m[0]);
    requireValue(typeof result !== 'number' || Number.isSafeInteger(result), 'JSON numbers must be safe integers; use strings for uint64.');
    return result;
  };
  const result = value(0); ws(); requireValue(i === text.length, 'Invalid JSON.'); return result;
}

export function canonical(value: any): string {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  return JSON.stringify(value);
}

export function safePath(input: string): string {
  requireValue(typeof input === 'string' && input.length > 0 && !input.includes('\0') && !input.split(path.sep).includes('..'), 'Unsafe path.');
  const full = path.resolve(input); let p = path.parse(full).root;
  for (const part of full.slice(p.length).split(path.sep)) {
    p = path.join(p, part);
    if (fs.existsSync(p) || (() => { try { fs.lstatSync(p); return true; } catch { return false; } })()) {
      requireValue(!fs.lstatSync(p).isSymbolicLink(), 'Symlink paths are refused.');
    }
  }
  return full;
}

export function privateDirectory(input: string, create = false): string {
  const p = safePath(input);
  if (create && !fs.existsSync(p)) fs.mkdirSync(p, { mode: 0o700 });
  const stat = fs.lstatSync(p);
  requireValue(stat.isDirectory() && (stat.mode & 0o077) === 0 && stat.uid === process.getuid?.(), 'Wallet/output directory must be owned by you and mode 0700.');
  return p;
}

export function readSafe(input: string, secret = false): string {
  const p = safePath(input); const fd = fs.openSync(p, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(fd);
    requireValue(stat.isFile() && stat.size <= 1024 * 1024 && stat.nlink === 1, 'Unsafe file type, link count or size.');
    if (secret) requireValue((stat.mode & 0o077) === 0 && stat.uid === process.getuid?.(), 'Wallet must be owned by you and mode 0600.');
    return fs.readFileSync(fd, 'utf8');
  } finally { fs.closeSync(fd); }
}

export function writeExclusive(input: string, value: any): void {
  const p = safePath(input); const dir = privateDirectory(path.dirname(p));
  const tmp = path.join(dir, '.kcli-' + randomBytes(16).toString('hex'));
  const fd = fs.openSync(tmp, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW, 0o600);
  try {
    fs.writeFileSync(fd, JSON.stringify(value, null, 2) + '\n'); fs.fsyncSync(fd);
    // link is atomic and fails on any existing destination, including a dangling symlink.
    fs.linkSync(tmp, p);
    const dfd = fs.openSync(dir, fs.constants.O_RDONLY); try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); }
  } finally { fs.closeSync(fd); fs.unlinkSync(tmp); }
}
