import { Command } from 'commander';
import { hiddenInput } from './secret-input';
import { NamedWallets } from './named-wallets';
import { readSafe, RefusalError, requireValue, strictJson, writeExclusive } from './secure-files';
import { appendSignature, DeployPackage, loadManifest, mergePackages, MultisigContext, policyOperation, prepareAction, prepareDeploy, readPackage, reconcile, requireBootstrapReview, reviewDeploy, reviewPackage, signDeploy, submit, submitDeploy, transferOperation, treasuryInfo, validateInputs, verifyDeployment, writeManifest, preflight } from './multisig';
import { parseAmount } from './multisig-protocol';
import { multisigProvider, MultisigProvider, validateNetwork } from './multisig-network';

// Exit codes: 0 completed/verified, 1 refused/reverted/invalid input, 3 outcome not (yet) final -- reconcile.
function guarded(fn: (...args: any[]) => Promise<void> | void) {
  return async (...args: any[]) => {
    try { await fn(...args); }
    catch (error) {
      // Inputs and RPC responses may carry secrets or terminal controls; only bounded local diagnostics escape.
      const message = error instanceof RefusalError ? error.message : 'Operation refused: invalid input or unavailable local resource.';
      console.error(`Multisig error: ${message}`); process.exitCode = 1;
    }
  };
}
const output = (v: unknown) => console.log(JSON.stringify(v, null, 2));
function outcome(result: any): void {
  output(result);
  if (!['irreversible-and-verified'].includes(result.status)) process.exitCode = ['reverted', 'refused'].includes(result.status) ? 1 : 3;
}
function manifestOptions(command: Command): Command {
  return command.requiredOption('--manifest <file>', 'Independently verified treasury manifest')
    .option('--review <file>', 'Mainnet: Ed25519 attestation binding the exact manifest')
    .option('--review-key <sha256>', 'Mainnet: independently trusted review-key SPKI fingerprint');
}
function onlineOptions(command: Command): Command {
  return command.option('--network <name>', 'Required explicit profile: local, testnet or mainnet')
    .option('--rpc <url>', 'Required explicit RPC; saved configuration is never used')
    .option('--corroborating-rpc <url>', 'Mainnet: second independently operated reviewed RPC')
    .option('--timeout <seconds>', 'Command deadline for all reads (10-600)', '120');
}
function explicitOnline(options: any, program: Command): any {
  const result = { ...options };
  // Commander consumes same-named root options even after a nested command; accept only values given now.
  for (const name of ['network', 'rpc']) {
    if (result[name] === undefined && program.getOptionValueSource(name) === 'cli') result[name] = program.getOptionValue(name);
    requireValue(typeof result[name] === 'string' && result[name].length > 0, 'Provide explicit --network and --rpc for multisig online commands.');
  }
  requireValue(/^[1-9]\d{1,2}$/.test(result.timeout) && Number(result.timeout) >= 10 && Number(result.timeout) <= 600, 'Timeout must be 10-600 seconds.');
  return result;
}
function context(options: any): MultisigContext {
  const ctx = loadManifest(options.manifest, options.review, options.reviewKey);
  if (options.network !== undefined) requireValue(options.network === ctx.manifest.network.name, 'Explicit network does not match the manifest.');
  return ctx;
}
// One deadline per command: --timeout for the reads, plus --wait where a command waits for finality.
async function withProvider<T>(network: any, options: any, fn: (p: MultisigProvider) => Promise<T>, extraMs = 0): Promise<T> {
  const provider = multisigProvider(network, options.rpc, Date.now() + Number(options.timeout) * 1000 + extraMs, options.corroboratingRpc);
  try { return await fn(provider); } finally { provider.close(); }
}
function deployNetwork(options: any, inputs: any): any {
  if (options.network === 'mainnet') {
    requireValue(options.networkProfile, 'Mainnet bootstrap requires --network-profile with the two reviewed RPCs.');
    const network = strictJson(readSafe(options.networkProfile)); requireValue(validateNetwork(network) === 'mainnet', 'Network profile is not Mainnet.'); return network;
  }
  const network = { name: options.network, chainId: inputs.chainId }; validateNetwork(network); return network;
}
async function unlock(options: any, expected: string): Promise<any> {
  const store = new NamedWallets(options.vaultDir);
  requireValue(store.metadata(options.wallet).address === options.signer && options.signer === expected, 'Selected wallet does not match the requested signer.');
  return store.unlock(options.wallet, await hiddenInput('Wallet password: '));
}
function waitMs(options: any): number {
  requireValue(/^[1-9]\d{0,2}$/.test(options.wait) && Number(options.wait) <= 600, 'Wait must be 1-600 seconds.'); return Number(options.wait) * 1000;
}

export function registerMultisigCommands(program: Command): void {
  const ms = program.command('multisig').description('Contract-enforced N-of-M KOIN treasury; detached signing, no automatic wallet selection');

  manifestOptions(onlineOptions(ms.command('info').description('Verify code/flags/policy and read balance, Mana and nonce'))).action(guarded(async options => {
    options = explicitOnline(options, program); const ctx = context(options);
    output(await withProvider(ctx.manifest.network, options, p => treasuryInfo(ctx, p)));
  }));

  // ------------------------------------------------------------------------------------------- bootstrap
  onlineOptions(ms.command('prepare-deploy').description('Build the unsigned single-upload bootstrap for an unused treasury address'))
    .requiredOption('--artifact <dir>', 'Reproducible build output (contract.wasm, treasury.abi, inputs.json, artifact.json)')
    .requiredOption('--rc-limit <units>', 'Exact positive raw Mana limit for the upload')
    .option('--network-profile <file>', 'Mainnet: reviewed profile with two RPCs')
    .option('--out <file>', 'New package file; never overwrites').option('--dry-run', 'Display only')
    .action(guarded(async options => {
      options = explicitOnline(options, program);
      const inputs = strictJson(readSafe(options.artifact + '/inputs.json')); const network = deployNetwork(options, inputs); validateInputs(inputs, network);
      const pkg = await withProvider(network, options, p => prepareDeploy(options.artifact, network, p, options.rcLimit));
      output(await reviewDeploy(pkg));
      if (options.dryRun) { output({ dryRun: true, walletUnlocked: false, signed: false, submitted: false }); return; }
      requireValue(options.out, 'Provide --out or --dry-run.'); writeExclusive(options.out, pkg);
    }));
  ms.command('inspect-deploy <package>').description('Offline review of the exact bootstrap upload').action(guarded(async file => output(await reviewDeploy(readPackage(file)))));
  ms.command('sign-deploy <package>').description('Offline bootstrap signature by the treasury address key (not a member approval)')
    .requiredOption('--wallet <name>', 'Named wallet holding the treasury address key').requiredOption('--signer <address>', 'Expected treasury address')
    .requiredOption('--id <transaction-id>', 'Exact reviewed bootstrap ID').option('--vault-dir <directory>', 'Private named-wallet directory')
    .option('--review <file>').option('--review-key <sha256>').option('--out <file>').option('--dry-run', 'Review only; no wallet access')
    .action(guarded(async (file, options) => {
      const pkg: DeployPackage = readPackage(file); const review = await reviewDeploy(pkg); requireBootstrapReview(pkg, options.review, options.reviewKey); output(review);
      requireValue(options.id === review.id && options.signer === review.treasury && !review.signed, 'Confirm the exact unsigned bootstrap ID and treasury address.');
      if (options.dryRun) { output({ dryRun: true, walletUnlocked: false, signed: false, submitted: false }); return; }
      requireValue(options.out, 'Provide a new --out path.');
      const signed = await signDeploy(pkg, await unlock(options, review.treasury), options.id); writeExclusive(options.out, signed); output(await reviewDeploy(signed));
    }));
  onlineOptions(ms.command('submit-deploy <package>').description('Fresh unused-address preflight, then one exact bootstrap submission'))
    .option('--id <transaction-id>').option('--wait <seconds>', 'Wait for irreversible inclusion', '120')
    .option('--review <file>').option('--review-key <sha256>').option('--dry-run', 'Preflight only; no intent, no broadcast')
    .action(guarded(async (file, options) => {
      options = explicitOnline(options, program); const pkg: DeployPackage = readPackage(file); requireBootstrapReview(pkg, options.review, options.reviewKey);
      requireValue(options.network === pkg.network.name, 'Explicit network does not match the package.');
      if (!options.dryRun) requireValue(options.id, 'Submission requires --id.');
      const wait = options.dryRun ? 0 : waitMs(options);
      const result = await withProvider(pkg.network, options, p => submitDeploy(pkg, p, options.id, wait, !!options.dryRun), wait);
      output(result); if (!options.dryRun && result.status !== 'irreversible') process.exitCode = result.status === 'reverted' ? 1 : 3;
    }));
  onlineOptions(ms.command('verify-deployment <package>').description('Post-upload checklist on an irreversible block; writes the treasury manifest. Never funds.'))
    .requiredOption('--manifest-out <file>', 'New treasury manifest file').option('--review <file>').option('--review-key <sha256>')
    .option('--wait <seconds>', 'Wait until the observation block is irreversible (1-600)', '300')
    .action(guarded(async (file, options) => {
      options = explicitOnline(options, program); const pkg: DeployPackage = readPackage(file); requireBootstrapReview(pkg, options.review, options.reviewKey);
      requireValue(options.network === pkg.network.name, 'Explicit network does not match the package.');
      const wait = waitMs(options); const result = await withProvider(pkg.network, options, p => verifyDeployment(pkg, p, wait), wait);
      if (result.status === 'deployment-verified') {
        const fingerprint = writeManifest(options.manifestOut, result.manifest);
        result.manifestSha256 = fingerprint; result.manifestFile = 'written';
        if (pkg.network.name === 'mainnet') result.remaining.unshift('Mainnet: obtain an independent review attestation of this exact manifest before any member signing.');
      }
      output(result); if (result.status !== 'deployment-verified') process.exitCode = ['refused', 'reverted'].includes(result.status) ? 1 : 3; // incl. observation-not-irreversible -> 3
    }));

  // ------------------------------------------------------------------------------------------- payments
  const prepare = (name: string, description: string) => manifestOptions(onlineOptions(ms.command(name).description(description)))
    .requiredOption('--rc-limit <units>', 'Exact positive raw Mana limit (measured; never adjusted after signing)')
    .option('--note <text>', 'Unsigned local reference (not part of the signed transaction)')
    .option('--out <file>', 'New package file; never overwrites').option('--dry-run', 'Display only; nothing written');
  const finish = async (ctx: MultisigContext, options: any, operation: any) => {
    const pkg = await withProvider(ctx.manifest.network, options, p => prepareAction(ctx, p, operation, options.rcLimit, options.note ?? null));
    output(await reviewPackage(ctx, pkg));
    if (options.dryRun) { output({ dryRun: true, walletUnlocked: false, signed: false, submitted: false }); return; }
    requireValue(options.out, 'Provide --out or --dry-run.'); writeExclusive(options.out, pkg);
  };
  prepare('prepare-transfer', 'One KOIN transfer from the treasury; reads only, never unlocks or signs')
    .requiredOption('--to <address>', 'Independently verified recipient').requiredOption('--amount <koin>', 'Exact decimal KOIN amount (max 8 decimals)')
    .action(guarded(async options => {
      options = explicitOnline(options, program); const ctx = context(options);
      await finish(ctx, options, await transferOperation(ctx, options.to, parseAmount(options.amount)));
    }));
  prepare('prepare-policy', 'Atomic complete owner/threshold replacement, approved by the current quorum')
    .requiredOption('--policy <file>', 'Strict JSON {"owners": [...], "threshold": n}')
    .action(guarded(async options => {
      options = explicitOnline(options, program); const ctx = context(options);
      await finish(ctx, options, await policyOperation(ctx, strictJson(readSafe(options.policy))));
    }));
  manifestOptions(ms.command('inspect <package>').description('Offline decode: ID, action, amount, signers and quorum')).action(guarded(async (file, options) => output(await reviewPackage(context(options), readPackage(file)))));
  manifestOptions(ms.command('sign <package>').description('Offline approval of the exact reviewed ID with one explicit named wallet'))
    .requiredOption('--wallet <name>', 'Explicit named encrypted wallet').requiredOption('--signer <address>', 'Expected owner address')
    .requiredOption('--id <transaction-id>', 'Exact reviewed transaction ID').option('--vault-dir <directory>', 'Private named-wallet directory')
    .option('--out <file>', 'New signed package; inputs are never modified').option('--dry-run', 'Review only; no wallet access/unlock/signature')
    .action(guarded(async (file, options) => {
      const ctx = context(options); const pkg = readPackage(file); const review = await reviewPackage(ctx, pkg); output(review);
      requireValue(options.id === review.id, 'Confirm the exact reviewed transaction ID.');
      requireValue(review.owners.includes(options.signer), 'The requested signer is not a current owner.');
      requireValue(!review.signers.includes(options.signer), 'This identity has already signed.');
      if (options.dryRun) { output({ dryRun: true, walletUnlocked: false, signed: false, submitted: false }); return; }
      requireValue(options.out, 'Provide a new --out path.');
      const signed = await appendSignature(ctx, pkg, await unlock(options, options.signer), options.id); writeExclusive(options.out, signed); output(await reviewPackage(ctx, signed));
    }));
  manifestOptions(ms.command('merge <packages...>').description('Offline deterministic merge of approvals for the same transaction')).requiredOption('--out <file>', 'New output file')
    .action(guarded(async (files, options) => { const ctx = context(options); const merged = await mergePackages(ctx, files.map(readPackage)); writeExclusive(options.out, merged); output(await reviewPackage(ctx, merged)); }));
  manifestOptions(onlineOptions(ms.command('submit <package>').description('Fresh preflight; read-only dry-run or one exact submission')))
    .option('--id <transaction-id>', 'Explicit submission confirmation')
    .option('--wait <seconds>', 'Wait for irreversible verification', '120').option('--dry-run', 'Preflight only; no intent, no broadcast')
    .action(guarded(async (file, options) => {
      options = explicitOnline(options, program); const ctx = context(options); const pkg = readPackage(file);
      if (options.dryRun) { output(await withProvider(ctx.manifest.network, options, p => preflight(ctx, p, pkg))); output({ dryRun: true, walletUnlocked: false, signed: false, submitted: false }); return; }
      requireValue(options.id, 'Submission requires --id.');
      const wait = waitMs(options); outcome(await withProvider(ctx.manifest.network, options, p => submit(ctx, p, pkg, options.id, wait), wait));
    }));
  manifestOptions(onlineOptions(ms.command('reconcile <package>').description('Read-only canonical/irreversible outcome; never resends')))
    .option('--manifest-out <file>', 'Policy changes: write the verified new manifest snapshot')
    .action(guarded(async (file, options) => {
      options = explicitOnline(options, program); const ctx = context(options); const pkg = readPackage(file);
      if ((await reviewPackage(ctx, pkg)).action.kind === 'policy') requireValue(options.manifestOut, 'Policy packages: provide --manifest-out for the verified new manifest snapshot.');
      const result = await withProvider(ctx.manifest.network, options, p => reconcile(ctx, p, pkg));
      if (result.status === 'irreversible-and-verified' && result.manifest) {
        result.manifestSha256 = writeManifest(options.manifestOut, result.manifest); delete result.manifest;
      }
      outcome(result);
    }));
}
