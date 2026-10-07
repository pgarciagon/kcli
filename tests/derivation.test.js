const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

function derive(t, phrase, count) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'kcli-derivation-release-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  return spawnSync('kcli', ['derive-from-seed', phrase, '--num-accounts', String(count)], {
    env: { ...process.env, HOME: home, KOINOS_BASEDIR: home, NODE_NO_WARNINGS: '1' },
    encoding: 'utf8', timeout: 15000,
  });
}

test('Kondor derivation retains the pre-release ethers v5 public-address vectors', t => {
  // This public BIP-39 test vector is never a real wallet; do not log its keys.
  const phrase = Array(11).fill('abandon').concat('about').join(' ');
  const result = derive(t, phrase, 3);
  assert.equal(result.status, 0);
  assert.equal(result.error, undefined);
  assert.deepEqual([...result.stdout.matchAll(/Address:\s+(\S+)/g)].map(match => match[1]), [
    '1DFF1akeStY8SfomzFsSYsZPesQcbnF1vR',
    '15n9ZbL3xmLBCUFtVQUzXKox5WhFnyAba3',
    '16ADbKNuSCcDaapTdgAjTVpD8SjoQFTeEU',
  ]);
  for (let i = 0; i < 3; i++) assert.ok(result.stdout.includes(`m/44'/659'/${i}'/0/0`));
});

test('Kondor derivation still rejects a mnemonic with an invalid checksum', t => {
  const result = derive(t, Array(12).fill('abandon').join(' '), 1);
  assert.equal(result.error, undefined);
  assert.match(result.stderr, /Error deriving accounts/);
  assert.ok(!result.stdout.includes('Private Key:'));
  assert.ok(!result.stdout.includes('Address:'));
});
