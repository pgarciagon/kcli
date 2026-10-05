import * as crypto from 'crypto';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { Signer, utils } from 'koilib';
import { canonical, objectKeys, privateDirectory, readSafe, RefusalError, requireValue, strictJson, writeExclusive } from './secure-files';

const KDF = { name: 'scrypt', N: 131072, r: 8, p: 1, keyLength: 32 } as const;
const MAXMEM = 160 * 1024 * 1024;
export interface NamedVault {
  schema: number; name: string; address: string; createdAt: string;
  kdf: typeof KDF & { salt: string }; cipher: { name: string; iv: string; tag: string; ciphertext: string };
}

function hex(value: any, length: number): Buffer {
  requireValue(typeof value === 'string' && new RegExp(`^[0-9a-f]{${length * 2}}$`).test(value), 'Invalid vault encoding.');
  return Buffer.from(value, 'hex');
}
export function walletName(name: string): string {
  requireValue(/^[a-z][a-z0-9-]{0,39}$/.test(name) && !['default', 'wallet', 'config'].includes(name), 'Use a distinct lowercase wallet name (letters, digits, hyphens; up to 40 characters).');
  return name;
}
function aad(v: NamedVault): Buffer {
  return Buffer.from(canonical({ schema: v.schema, name: v.name, address: v.address, createdAt: v.createdAt, kdf: v.kdf, cipher: { name: v.cipher.name, iv: v.cipher.iv } }));
}
export function validateVault(v: NamedVault, expectedName: string): void {
  objectKeys(v, ['schema', 'name', 'address', 'createdAt', 'kdf', 'cipher']);
  objectKeys(v.kdf, ['name', 'N', 'r', 'p', 'keyLength', 'salt']);
  objectKeys(v.cipher, ['name', 'iv', 'tag', 'ciphertext']);
  requireValue(v.schema === 1 && walletName(v.name) === expectedName && utils.isChecksumAddress(v.address), 'Invalid wallet identity.');
  requireValue(typeof v.createdAt === 'string' && new Date(v.createdAt).toISOString() === v.createdAt, 'Invalid wallet creation date.');
  requireValue(Object.entries(KDF).every(([k, n]) => (v.kdf as any)[k] === n), 'Unsupported or unsafe KDF parameters.');
  requireValue(v.cipher.name === 'aes-256-gcm', 'Unsupported wallet cipher.');
  hex(v.kdf.salt, 32); hex(v.cipher.iv, 12); hex(v.cipher.tag, 16);
  requireValue(typeof v.cipher.ciphertext === 'string' && /^[0-9a-f]{100,104}$/.test(v.cipher.ciphertext) && v.cipher.ciphertext.length % 2 === 0, 'Invalid vault ciphertext.');
}
export function encryptNamed(signer: Signer, name: string, password: string): NamedVault {
  walletName(name);
  requireValue(typeof password === 'string' && password.length >= 12 && Buffer.byteLength(password) <= 1024, 'Use a password between 12 characters and 1024 bytes.');
  const v: NamedVault = { schema: 1, name, address: signer.getAddress(), createdAt: new Date().toISOString(),
    kdf: { ...KDF, salt: crypto.randomBytes(32).toString('hex') }, cipher: { name: 'aes-256-gcm', iv: crypto.randomBytes(12).toString('hex'), tag: '', ciphertext: '' } };
  const key = crypto.scryptSync(password, hex(v.kdf.salt, 32), 32, { ...KDF, maxmem: MAXMEM });
  const plain = Buffer.from(signer.getPrivateKey('wif'));
  try {
    const c = crypto.createCipheriv('aes-256-gcm', key, hex(v.cipher.iv, 12)); c.setAAD(aad(v));
    v.cipher.ciphertext = Buffer.concat([c.update(plain), c.final()]).toString('hex'); v.cipher.tag = c.getAuthTag().toString('hex');
    return v;
  } finally { key.fill(0); plain.fill(0); }
}
export function decryptNamed(v: NamedVault, name: string, password: string): Signer {
  validateVault(v, name); requireValue(typeof password === 'string' && Buffer.byteLength(password) <= 1024, 'Invalid unlock input.');
  const key = crypto.scryptSync(password, hex(v.kdf.salt, 32), 32, { ...KDF, maxmem: MAXMEM });
  let plain: Buffer | undefined; let unauthenticated: Buffer | undefined;
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', key, hex(v.cipher.iv, 12)); d.setAAD(aad(v)); d.setAuthTag(hex(v.cipher.tag, 16));
    unauthenticated = d.update(Buffer.from(v.cipher.ciphertext, 'hex'));
    plain = Buffer.concat([unauthenticated, d.final()]);
    const s = Signer.fromWif(plain.toString('utf8'));
    requireValue(s.getAddress() === v.address, 'Wallet key/address mismatch.'); return s;
  } catch { throw new RefusalError('Wallet unlock failed: wrong password, corrupt vault or address mismatch.'); }
  finally { key.fill(0); plain?.fill(0); unauthenticated?.fill(0); }
}

export class NamedWallets {
  constructor(readonly directory = path.join(os.homedir(), '.kcli', 'wallets')) {}
  file(name: string): string { return path.join(privateDirectory(this.directory), walletName(name) + '.json'); }
  read(name: string): NamedVault { const v = strictJson(readSafe(this.file(name), true)); validateVault(v, name); return v; }
  metadata(name: string) { const v = this.read(name); return { name: v.name, address: v.address, createdAt: v.createdAt, schema: v.schema }; }
  list() { privateDirectory(this.directory); return fs.readdirSync(this.directory).filter(n => n.endsWith('.json')).sort().map(n => this.metadata(n.slice(0, -5))); }
  save(signer: Signer, name: string, password: string) {
    // Never create or alter the existing default wallet/configuration.
    const parent = path.dirname(this.directory); privateDirectory(parent, true); privateDirectory(this.directory, true);
    const file = this.file(name); requireValue(!fs.existsSync(file), 'Named wallet already exists.');
    writeExclusive(file, encryptNamed(signer, name, password)); return this.metadata(name);
  }
  unlock(name: string, password: string): Signer { return decryptNamed(this.read(name), name, password); }
}

export function randomSigner(): Signer {
  for (let i = 0; i < 5; i++) {
    const scalar = crypto.randomBytes(32);
    try { return new Signer({ privateKey: scalar.toString('hex') }); } catch { /* invalid curve scalar; resample */ }
    finally { scalar.fill(0); }
  }
  throw new RefusalError('Unable to generate a signing identity.');
}
