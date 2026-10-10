const test = require('node:test');
const assert = require('node:assert/strict');
const { mkdtemp, mkdir, writeFile, rm } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const { Provider, Serializer } = require('koilib');
const { FundClient, parseProjectId, parsePercentage, validateVoteChange, validateFundAbi, formatFundVotes, timestampIso } = require('../dist/fund.js');
const { CHAIN_ID, TESTNET_ID, FUND, SIGNER, VOTER, makeAbi, project, createRpc } = require('./fund-fixture');

const context = rpc => ({ networkName: 'mainnet', rpc, definition: { chainId: CHAIN_ID },
  contracts: { fund: FUND, koin: '19GYjDBVXU7keLbYvMLazsGQn3GTWHjHkK', vhp: '12Y5vW6gk8GceH53YfRkRre2Rrcsgw7Naq' } });
const vote = (project_id, weight, expiration = '1000') => ({ project_id, weight, expiration });

async function setup(t, options = {}) {
  const rpc = await createRpc(options);
  const home = await mkdtemp(path.join(tmpdir(), 'kcli-fund-test-'));
  t.after(async () => { await rpc.close(); await rm(home, { recursive: true, force: true }); });
  return { rpc, home };
}

async function run(home, rpc, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.resolve(__dirname, '../dist/index.js'), '--rpc', rpc.url, ...args], {
      env: { ...process.env, HOME: home, NODE_NO_WARNINGS: '1' }, stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '', stderr = '';
    const timer = setTimeout(() => { child.kill(); reject(new Error('CLI test timed out')); }, 15000);
    child.stdout.on('data', data => { stdout += data; });
    child.stderr.on('data', data => { stderr += data; });
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('close', code => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
  });
}

async function saveSyntheticWallet(home, address = VOTER) {
  const folder = path.join(home, '.kcli');
  await mkdir(folder, { recursive: true });
  const password = 'synthetic-test-password';
  const salt = crypto.randomBytes(32), iv = crypto.randomBytes(16);
  const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(SIGNER.getPrivateKey('wif'), 'utf8'), cipher.final()]).toString('hex');
  await writeFile(path.join(folder, 'wallet.json'), JSON.stringify({ address, encryptedKey: { encrypted, salt: salt.toString('hex'), iv: iv.toString('hex'), authTag: cipher.getAuthTag().toString('hex') } }), { mode: 0o600 });
  const passwordFile = path.join(folder, 'fixture-password');
  await writeFile(passwordFile, password, { mode: 0o600 });
  return passwordFile;
}

test('input validation rejects malformed IDs and percentages without numeric coercion', () => {
  for (const id of ['0', '-1', '1.1', '1e2', '4294967296', ' 1', '01']) assert.throws(() => parseProjectId(id));
  assert.equal(parseProjectId('4294967295'), 4294967295);
  for (const percent of ['-5', '101', '3', '50.1', '5e1', ' 50', 'Infinity']) assert.throws(() => parsePercentage(percent));
  assert.equal(parsePercentage('0'), 0);
  assert.equal(parsePercentage('100'), 100);
});

test('replacing and renewing votes counts expired allocations and respects the total budget', () => {
  const votes = [vote(1, 12), vote(2, 8)];
  const change = validateVoteChange(votes, project(1), 60, 1n);
  assert.equal(change.totalWeight, 20);
  assert.equal(validateVoteChange(votes, project(1), 0, 1n).totalWeight, 8);
  assert.throws(() => validateVoteChange(votes, project(3), 5, 1n), /exceeding 100/);
  assert.throws(() => validateVoteChange(votes, project(1), 65, 1n), /exceeding 100/);
  assert.throws(() => validateVoteChange([], project(1), 0, 1n), /No vote/);
  assert.throws(() => validateVoteChange([], project(1), 5, 0n), /positive KOIN or VHP/);
  assert.throws(() => validateVoteChange([vote(1, 1), vote(1, 1)], project(1), 5, 1n), /Invalid existing/);
});

test('past projects permit only removal of an existing vote, including zero token balance', () => {
  const past = project(1, { status: 2 });
  assert.equal(validateVoteChange([vote(1, 10)], past, 0, 0n).totalWeight, 0);
  assert.throws(() => validateVoteChange([vote(1, 10)], past, 50, 10n), /Past projects/);
});

test('fund formatting retains fractional base units and uint64 precision', () => {
  assert.equal(formatFundVotes('1'), '0.0000000005');
  assert.equal(formatFundVotes('18446744073709551615'), '9223372036.8547758075');
  assert.equal(timestampIso('2000000000000'), '2033-05-18T03:33:20.000Z');
  assert.throws(() => timestampIso('18446744073709551615'), /date range/);
});

test('ABI validation rejects redirected writes, writes disguised as reads, and altered voter encoding', () => {
  for (const mutate of [
    abi => { abi.methods.update_vote.entry_point = 1; },
    abi => { abi.methods.get_projects.read_only = false; },
    abi => { abi.koilib_types.nested.fund.nested.update_vote_arguments.fields.voter.id = 4; },
    abi => { abi.koilib_types.nested.fund.nested.update_vote_arguments.fields.extra = { id: 4, type: 'string' }; },
  ]) { const abi = makeAbi(); mutate(abi); assert.throws(() => validateFundAbi(abi), /Incompatible fund/); }
});

test('deployed-style ABI without display annotations decodes addresses and uint64 strings', async t => {
  const abi = makeAbi();
  for (const type of Object.values(abi.koilib_types.nested.fund.nested)) {
    for (const field of Object.values(type.fields || {})) delete field.options;
  }
  const { rpc } = await setup(t, { abi, projects: [project(1, { monthly_payment: '18446744073709551615' })] });
  const fund = await FundClient.connect(context(rpc.url), new Provider(rpc.url));
  const result = await fund.project(1);
  assert.equal(result.creator, VOTER);
  assert.equal(result.monthly_payment, '18446744073709551615');
});

test('real koilib decoding handles pagination, votes, and zero-valued project status', async t => {
  const { rpc } = await setup(t, { projects: [project(1), project(2), project(3), project(4, { status: 0 })] });
  const fund = await FundClient.connect(context(rpc.url), new Provider(rpc.url));
  const first = await fund.projects({ status: 'active', order: 'votes', limit: 2, descending: true });
  assert.equal(first.nextCursor, 'page-2');
  const all = await fund.projects({ status: 'active', order: 'votes', limit: 2, descending: true, all: true });
  assert.deepEqual(all.projects.map(p => p.id), [1, 2, 3]);
  assert.equal((await fund.project(4)).status, 0);
  const upcoming = await fund.projects({ status: 'upcoming', order: 'date', limit: 2, descending: false });
  assert.deepEqual(upcoming.projects.map(p => p.id), [4]);
  assert.deepEqual(await fund.votes(VOTER), []);
  assert.equal(rpc.state.submitted.length, 0);
});

test('repeated pagination cursors fail instead of looping', async t => {
  const { rpc } = await setup(t, { repeatCursor: true });
  const fund = await FundClient.connect(context(rpc.url), new Provider(rpc.url));
  await assert.rejects(fund.projects({ status: 'active', order: 'votes', limit: 2, descending: true, all: true }), /repeated cursor/);
});

test('CLI read commands emit parseable JSON without wallet credentials', async t => {
  const { rpc, home } = await setup(t, { votes: [vote(1, 10, '2000000000000')] });
  for (const args of [['fund-info'], ['proposals', '--all', '--limit', '2'], ['proposal', '1'], ['votes', VOTER]]) {
    const result = await run(home, rpc, [...args, '--json']);
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).network, 'mainnet');
  }
  assert.equal(rpc.state.submitted.length, 0);
});

test('CLI dry-run uses a public address and never reads a password file or submits', async t => {
  const { rpc, home } = await setup(t);
  const result = await run(home, rpc, ['vote', '1', '--percent', '50', '--address', VOTER, '--dry-run', '--password-file', '/does-not-exist']);
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /wallet not unlocked/);
  assert.doesNotMatch(result.stdout, /Enter wallet password/);
  assert.match(result.stdout, /"payer":/);
  assert.doesNotMatch(result.stdout, /"signatures":/);
  assert.equal(rpc.state.submitted.length, 0);
});

test('dry-run uses only the wallet public address even when encrypted data is invalid', async t => {
  const { rpc, home } = await setup(t);
  await mkdir(path.join(home, '.kcli'));
  await writeFile(path.join(home, '.kcli/wallet.json'), JSON.stringify({ address: VOTER, encryptedKey: {} }));
  const result = await run(home, rpc, ['vote', '1', '--percent', '50', '--dry-run']);
  assert.equal(result.code, 0, result.stderr);
  assert.equal(rpc.state.submitted.length, 0);
});

test('wrong chain fails before metadata or wallet unlock', async t => {
  const { rpc, home } = await setup(t, { chainId: TESTNET_ID });
  await saveSyntheticWallet(home);
  const result = await run(home, rpc, ['vote', '1', '--percent', '50', '--yes', '--password-file', '/does-not-exist']);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /chain ID does not match/);
  assert.deepEqual(rpc.calls.map(c => c.method), ['chain.get_chain_id']);
});

test('unconfigured testnet cannot silently use the mainnet fund', async t => {
  const { rpc, home } = await setup(t, { chainId: TESTNET_ID });
  const result = await run(home, rpc, ['--network', 'testnet', 'fund-info']);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /No verified fund contract/);
  assert.equal(rpc.calls.length, 0);
});

test('explicit compatible testnet deployment works without weakening the chain guard', async t => {
  const { rpc, home } = await setup(t, { chainId: TESTNET_ID });
  const result = await run(home, rpc, ['--network', 'testnet', 'fund-info', '--fund-contract', FUND, '--json']);
  assert.equal(result.code, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).network, 'testnet');
  assert.equal(rpc.state.submitted.length, 0);
});

test('chain changes during preparation stop the signing flow before password access', async t => {
  const { rpc, home } = await setup(t, { chainIds: [CHAIN_ID, CHAIN_ID, TESTNET_ID] });
  await saveSyntheticWallet(home);
  const result = await run(home, rpc, ['vote', '1', '--percent', '50', '--yes', '--password-file', '/does-not-exist']);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /chain ID does not match/);
  assert.equal(rpc.state.submitted.length, 0);
});

test('public voter override cannot be used for a signed vote', async t => {
  const { rpc, home } = await setup(t);
  const result = await run(home, rpc, ['vote', '1', '--percent', '50', '--address', VOTER, '--yes']);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /only available with --dry-run/);
  assert.equal(rpc.calls.length, 0);
});

test('invalid inputs and allocation excess fail with nonzero exit before password access', async t => {
  const { rpc, home } = await setup(t, { votes: [vote(2, 20)] });
  for (const [id, percent] of [['0', '50'], ['1', '51'], ['1', '50']]) {
    const result = await run(home, rpc, ['vote', id, '--percent', percent, '--address', VOTER, '--dry-run']);
    assert.equal(result.code, 1);
  }
  assert.equal(rpc.state.submitted.length, 0);
});

test('RPC failures and incompatible ABI fail without submission', async t => {
  const { rpc, home } = await setup(t, { noAbi: true });
  const result = await run(home, rpc, ['vote', '1', '--percent', '50', '--dry-run', '--address', VOTER]);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /no ABI/);
  const abi = makeAbi(); abi.methods.update_vote.entry_point = 1;
  const other = await setup(t, { abi });
  const incompatible = await run(other.home, other.rpc, ['vote', '1', '--percent', '50', '--dry-run', '--address', VOTER]);
  assert.equal(incompatible.code, 1);
  assert.equal(other.rpc.state.submitted.length, 0);
  const failed = await setup(t, { failMethod: 'chain.read_contract' });
  const failure = await run(failed.home, failed.rpc, ['proposal', '1']);
  assert.equal(failure.code, 1);
  assert.equal(failed.rpc.state.submitted.length, 0);
});

test('bundled fund read interface matches independent wire schemas and exposes no writes', async () => {
  const abi = require('../src/abis/fund-read.json');
  const validated = validateFundAbi(abi, true);
  const expected = makeAbi();
  delete expected.methods.update_vote;
  delete expected.koilib_types.nested.fund.nested.update_vote_arguments;
  delete expected.koilib_types.nested.fund.nested.update_vote_result;
  assert.deepEqual(validated, expected);
  assert.ok(Object.values(validated.methods).every(method => method.read_only));
  assert.throws(() => validateFundAbi(abi), /update_vote/);
});

test('missing ABI supports every read command with provenance and clean JSON, but never touches wallets', async t => {
  const { rpc, home } = await setup(t, { noAbi: true, votes: [vote(1, 10, '2000000000000')] });
  const folder = path.join(home, '.kcli');
  await mkdir(folder);
  const wallet = JSON.stringify({ address: VOTER, encryptedKey: { deliberatelyInvalid: true } });
  const config = JSON.stringify({ network: 'mainnet', mainProducerAddress: VOTER });
  await writeFile(path.join(folder, 'wallet.json'), wallet);
  await writeFile(path.join(folder, 'config.json'), config);
  for (const args of [['fund-info'], ['proposals', '--all', '--limit', '2'], ['proposal', '1'], ['votes', VOTER], ['votes']]) {
    const result = await run(home, rpc, [...args, '--json']);
    assert.equal(result.code, 0, result.stderr);
    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.abi_source, 'bundled-read-only');
    assert.match(result.stderr, /RPC ABI index is empty/);
    assert.ok(!result.stdout.includes('Unlocking'));
    if (args[0] === 'proposals') assert.deepEqual(parsed.projects.map(project => project.id), [1, 2, 3]);
  }
  const { readFile } = require('node:fs/promises');
  assert.equal(await readFile(path.join(folder, 'wallet.json'), 'utf8'), wallet);
  assert.equal(await readFile(path.join(folder, 'config.json'), 'utf8'), config);
  assert.ok(!rpc.calls.some(call => ['chain.get_account_nonce', 'chain.submit_transaction'].includes(call.method)));
});

test('bundled read connection cannot prepare a vote or expose update_vote', async t => {
  const { rpc } = await setup(t, { noAbi: true });
  const fund = await FundClient.connect(context(rpc.url), new Provider(rpc.url), undefined, true);
  assert.equal(fund.contract.functions.update_vote, undefined);
  assert.equal(fund.abiSource, 'bundled-read-only');
  const before = rpc.calls.length;
  await assert.rejects(fund.prepareVote(1, 50, VOTER), /read-only/);
  assert.equal(rpc.calls.length, before);
  assert.equal(rpc.state.submitted.length, 0);
});

test('missing ABI never falls back for signed votes or vote dry-runs', async t => {
  const { rpc, home } = await setup(t, { noAbi: true });
  await saveSyntheticWallet(home);
  for (const args of [['--dry-run', '--address', VOTER], ['--yes', '--password-file', '/deliberately/missing/password']]) {
    const result = await run(home, rpc, ['vote', '1', '--percent', '50', ...args]);
    assert.equal(result.code, 1); assert.match(result.stderr, /Voting and custom deployments require/);
    assert.ok(!result.stdout.includes('Unlocking')); assert.ok(!result.stderr.includes('bundled read-only'));
  }
  assert.ok(!rpc.calls.some(call => call.method === 'chain.read_contract'));
  assert.equal(rpc.state.submitted.length, 0);
});

test('bundled fallback is pinned to the actual mainnet chain and known fund address', async t => {
  for (const options of [{ chainId: TESTNET_ID }, { chainId: 'unknown-chain' }]) {
    const { rpc, home } = await setup(t, { ...options, noAbi: true });
    const result = await run(home, rpc, ['proposals']);
    assert.equal(result.code, 1); assert.match(result.stderr, /chain ID does not match/);
    assert.equal(rpc.calls.length, 1);
  }
  const { rpc, home } = await setup(t, { noAbi: true, chainId: TESTNET_ID });
  const testnet = await run(home, rpc, ['--network', 'testnet', 'proposals', '--fund-contract', FUND]);
  assert.equal(testnet.code, 1); assert.match(testnet.stderr, /no ABI/);
  const main = await setup(t, { noAbi: true });
  const other = await run(main.home, main.rpc, ['proposals', '--fund-contract', VOTER]);
  assert.equal(other.code, 1); assert.match(other.stderr, /no ABI/);
  assert.ok(!main.rpc.calls.some(call => call.method === 'chain.read_contract'));
});

test('metadata-backed reads remain preferred and incompatible or malformed metadata is not replaced', async t => {
  const ordinary = await setup(t);
  const result = await run(ordinary.home, ordinary.rpc, ['proposals', '--json']);
  assert.equal(result.code, 0); assert.equal(JSON.parse(result.stdout).abi_source, 'rpc-metadata');
  assert.equal(result.stderr, '');
  for (const mutate of [abi => { abi.methods.get_projects.entry_point = 1; },
    abi => { abi.methods.get_projects.read_only = false; }, abi => { delete abi.koilib_types; }]) {
    const abi = makeAbi(); mutate(abi);
    const { rpc, home } = await setup(t, { abi });
    const failure = await run(home, rpc, ['proposals']);
    assert.equal(failure.code, 1); assert.match(failure.stderr, /Incompatible fund/);
    assert.ok(!rpc.calls.some(call => call.method === 'chain.read_contract'));
  }
  for (const metadataAbi of ['null', 'false', '0', '{invalid JSON']) {
    const { rpc, home } = await setup(t, { metadataAbi });
    const failure = await run(home, rpc, ['proposals']);
    assert.equal(failure.code, 1); assert.ok(!failure.stderr.includes('bundled read-only'));
    assert.ok(!rpc.calls.some(call => call.method === 'chain.read_contract'));
  }
});

test('RPC errors and missing JSON-RPC result envelopes remain errors, never an empty proposal list', async t => {
  for (const options of [{ failMethod: 'contract_meta_store.get_contract_meta' }, { noAbi: true, failMethod: 'chain.read_contract' },
    { noAbi: true, missingReadResult: true }]) {
    const { rpc, home } = await setup(t, options);
    const result = await run(home, rpc, ['proposals', '--json']);
    assert.equal(result.code, 1); assert.ok(!result.stdout.includes('projects'));
    assert.equal(rpc.state.submitted.length, 0);
  }
});

test('explicit empty protobuf results are valid empty proposal and vote lists', async t => {
  const { rpc, home } = await setup(t, { noAbi: true, emptyReadResult: true });
  const proposals = await run(home, rpc, ['proposals', '--json']);
  assert.equal(proposals.code, 0, proposals.stderr); assert.deepEqual(JSON.parse(proposals.stdout).projects, []);
  const votes = await run(home, rpc, ['votes', VOTER, '--json']);
  assert.equal(votes.code, 0, votes.stderr); assert.deepEqual(JSON.parse(votes.stdout).votes, []);
});

test('protobuf-omitted empty result bytes decode as empty votes with or without logs', async t => {
  for (const readLogs of [undefined, [], ['Synthetic successful read']]) {
    const { rpc, home } = await setup(t, { omitEmptyReadResult: true, readLogs });
    const fund = await FundClient.connect(context(rpc.url), new Provider(rpc.url));
    assert.deepEqual(await fund.votes(VOTER), []);
    const result = await run(home, rpc, ['votes', VOTER, '--json']);
    assert.equal(result.code, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout).votes, []);
    assert.equal(rpc.state.submitted.length, 0);
  }
});

test('read-only ABI fallback also accepts protobuf-omitted empty list bytes', async t => {
  const { rpc, home } = await setup(t, { noAbi: true, omitEmptyReadResult: true, projects: [] });
  for (const args of [['votes', VOTER], ['proposals']]) {
    const result = await run(home, rpc, [...args, '--json']);
    assert.equal(result.code, 0, result.stderr);
    const data = JSON.parse(result.stdout);
    assert.equal(data.abi_source, 'bundled-read-only');
    assert.deepEqual(args[0] === 'votes' ? data.votes : data.projects, []);
  }
  assert.equal(rpc.state.submitted.length, 0);
});

test('CLI vote --percent 100 10 dry-run succeeds when empty vote bytes are omitted', async t => {
  const { rpc, home } = await setup(t, { omitEmptyReadResult: true, projects: [project(10)] });
  const result = await run(home, rpc, ['vote', '--percent', '100', '10', '--address', VOTER,
    '--dry-run', '--password-file', '/deliberately/missing/password']);
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /Allocation: 0% -> 100%/);
  assert.match(result.stdout, /wallet not unlocked; transaction not signed or submitted/);
  const transaction = JSON.parse(result.stdout.slice(result.stdout.indexOf('{'), result.stdout.lastIndexOf('}') + 1));
  assert.equal(transaction.signatures?.length || 0, 0);
  assert.equal(rpc.state.submitted.length, 0);
});

test('nonempty vote allocations remain authoritative with protobuf-default omission', async t => {
  const { rpc, home } = await setup(t, { omitEmptyReadResult: true, projects: [project(10)], votes: [vote(2, 20)] });
  const result = await run(home, rpc, ['vote', '--percent', '100', '10', '--address', VOTER, '--dry-run']);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /exceeding 100%/);
  assert.equal(rpc.state.submitted.length, 0);
});

test('valid standard and URL-safe base64 vote bytes accept padded and unpadded encodings', async t => {
  const votes = [vote(10, 20, '18446744073709551615')];
  const serializer = new Serializer(makeAbi().koilib_types);
  const base64 = Buffer.from(await serializer.serialize({ votes }, 'fund.get_user_votes_result')).toString('base64');
  for (const result of [base64, base64.replace(/=+$/, ''), base64.replace(/\+/g, '-').replace(/\//g, '_'),
    base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')]) {
    const { rpc } = await setup(t, { readResponse: { result } });
    const fund = await FundClient.connect(context(rpc.url), new Provider(rpc.url));
    assert.deepEqual(await fund.votes(VOTER), votes);
    assert.equal(rpc.state.submitted.length, 0);
  }
});

test('malformed contract read responses never become empty votes', async t => {
  for (const readResponse of [null, false, 1, '', [], { result: null }, { result: 0 }, { result: false },
    { logs: null }, { logs: 'bad logs' }, { logs: [1] }, { error: 'failed read' },
    { result: '', error: 'failed read' }, { unknown: 'not a read response' },
    { result: 'not*base64' }, { result: 'A' }, { result: 'AQ=' }, { result: 'AB==' }]) {
    const { rpc } = await setup(t, { readResponse });
    const fund = await FundClient.connect(context(rpc.url), new Provider(rpc.url));
    await assert.rejects(fund.votes(VOTER));
    assert.equal(rpc.state.submitted.length, 0);
  }
});

test('missing envelope or malformed vote response blocks before wallet unlock and submission', async t => {
  for (const options of [{ missingReadResult: true }, { readResponse: { logs: [1] } }]) {
    const { rpc, home } = await setup(t, options);
    await mkdir(path.join(home, '.kcli'), { recursive: true });
    const wallet = JSON.stringify({ address: VOTER, encryptedKey: { intentionally: 'invalid' } });
    await writeFile(path.join(home, '.kcli/wallet.json'), wallet);
    const result = await run(home, rpc, ['vote', '--percent', '100', '10', '--yes',
      '--password-file', '/deliberately/missing/password']);
    assert.equal(result.code, 1);
    assert.doesNotMatch(result.stderr, /password|decrypt|unlock/i);
    assert.equal(rpc.state.submitted.length, 0);
  }
});

test('synthetic signed vote and removal handle omitted empty vote bytes', async t => {
  const { rpc, home } = await setup(t, { omitEmptyReadResult: true, projects: [project(10)] });
  const passwordFile = await saveSyntheticWallet(home);
  for (const percent of ['100', '0']) {
    const result = await run(home, rpc, ['vote', '--percent', percent, '10', '--password-file', passwordFile, '--yes']);
    assert.equal(result.code, 0, result.stderr);
    assert.match(result.stdout, /Allocation readback verified/);
  }
  assert.equal(rpc.state.submitted.length, 2);
  assert.deepEqual(rpc.state.votes, []);
});

test('a wallet address that does not match the decrypted key cannot sign', async t => {
  const { rpc, home } = await setup(t);
  const passwordFile = await saveSyntheticWallet(home, FUND);
  const result = await run(home, rpc, ['vote', '1', '--percent', '50', '--password-file', passwordFile, '--yes']);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /key does not match/);
  assert.equal(rpc.state.submitted.length, 0);
});

test('synthetic signed vote/update/removal round trip verifies signature, receipt, and readback', async t => {
  const { rpc, home } = await setup(t);
  const passwordFile = await saveSyntheticWallet(home);
  for (const percent of ['50', '75', '75', '0']) {
    const result = await run(home, rpc, ['vote', '1', '--percent', percent, '--password-file', passwordFile, '--yes']);
    assert.equal(result.code, 0, result.stderr);
    assert.match(result.stdout, /Included in block 123/);
    assert.match(result.stdout, /Allocation readback verified/);
  }
  assert.equal(rpc.state.submitted.length, 4);
  assert.deepEqual(rpc.state.votes, []);
});

test('no-wait distinguishes submission from verification', async t => {
  const { rpc, home } = await setup(t);
  const passwordFile = await saveSyntheticWallet(home);
  const result = await run(home, rpc, ['vote', '1', '--percent', '50', '--password-file', passwordFile, '--yes', '--no-wait']);
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /have not been verified/);
  assert.doesNotMatch(result.stdout, /readback verified/);
  assert.equal(rpc.state.submitted.length, 1);
});

test('included reversions, missing receipts, and readback mismatch cannot report success', async t => {
  for (const failure of [{ includedReverted: true }, { noReceipt: true }, { noApply: true }]) {
    const { rpc, home } = await setup(t, failure);
    const passwordFile = await saveSyntheticWallet(home);
    const result = await run(home, rpc, ['vote', '1', '--percent', '50', '--password-file', passwordFile, '--yes']);
    assert.equal(result.code, 1);
    assert.doesNotMatch(result.stdout, /Allocation readback verified/);
    assert.equal(rpc.state.submitted.length, 1);
  }
});

test('submission rejection and unknown RPC outcomes do not trigger a resend', async t => {
  for (const failure of [{ reverted: true }, { rpcError: true }]) {
    const { rpc, home } = await setup(t, failure);
    const passwordFile = await saveSyntheticWallet(home);
    const result = await run(home, rpc, ['vote', '1', '--percent', '50', '--password-file', passwordFile, '--yes']);
    assert.equal(result.code, 1);
    assert.doesNotMatch(result.stdout, /Vote submitted/);
    assert.equal(rpc.state.submitted.length, 1);
  }
});

test('inclusion timeout reports uncertainty and submits only once', async t => {
  const { rpc, home } = await setup(t, { timeout: true });
  const passwordFile = await saveSyntheticWallet(home);
  const result = await run(home, rpc, ['vote', '1', '--percent', '50', '--password-file', passwordFile, '--yes', '--wait-timeout', '1']);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /Inclusion is unconfirmed/);
  assert.doesNotMatch(result.stdout, /Allocation readback verified/);
  assert.equal(rpc.state.submitted.length, 1);
});

test('mana and RC limits are validated before unlocking', async t => {
  for (const [options, limit] of [[{ mana: '0' }, undefined], [{ mana: '10' }, '11'], [{ mana: '10' }, '0']]) {
    const { rpc, home } = await setup(t, options);
    const result = await run(home, rpc, ['vote', '1', '--percent', '50', '--dry-run', '--address', VOTER, ...(limit ? ['--rc-limit', limit] : [])]);
    assert.equal(result.code, 1);
    assert.equal(rpc.state.submitted.length, 0);
  }
});
