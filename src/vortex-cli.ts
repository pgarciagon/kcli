import { Command } from 'commander';
import { Signer } from 'koilib';
import { hiddenInput } from './secret-input';
import { NamedWallets, randomSigner } from './named-wallets';
import { readSafe, RefusalError, requireValue, strictJson, writeExclusive } from './secure-files';
import { appendSignature, encodeAction, loadVortex, mergePackages, preflightVortex, prepareVortex, readPackage, reconcileVortex, reviewPackage, submitVortex, vortexProvider } from './vortex';

async function newPassword(): Promise<string> {
  const first = await hiddenInput('New wallet password: '); const second = await hiddenInput('Confirm wallet password: ');
  requireValue(first === second, 'Passwords do not match.'); return first;
}
function guarded(fn: (...args: any[]) => Promise<void> | void) {
  return async (...args: any[]) => {
    try { await fn(...args); }
    catch (error) {
      // Inputs/RPC responses can include secrets or terminal controls; only bounded local diagnostics escape.
      const message = error instanceof RefusalError ? error.message : 'Operation refused: invalid input or unavailable local resource.';
      console.error(`Vortex/wallet error: ${message}`); process.exitCode = 1;
    }
  };
}
const output = (v: unknown) => console.log(JSON.stringify(v, null, 2));
function bind(command: Command): Command {
  return command.requiredOption('--manifest <file>', 'Independently reviewed deployment manifest')
    .requiredOption('--abi <file>', 'Exact reviewed deployed ABI file')
    .option('--review <file>', 'Mainnet Ed25519 attestation binding the exact manifest')
    .option('--review-key <sha256>', 'Independently trusted review-key SPKI fingerprint');
}
function online(command: Command): Command {
  return command.option('--network <name>', 'Required explicit local or mainnet profile')
    .option('--rpc <url>', 'Required explicit primary RPC; saved configuration is not used')
    .option('--corroborating-rpc <url>', 'Required independently operated reviewed HTTPS RPC on mainnet')
    .requiredOption('--contract <address>', 'Exact reviewed contract');
}
function explicitOnline(options: any, program: Command): any {
  const result = { ...options };
  // Commander consumes same-named root options even after a nested command.
  // Accept only values actually supplied on this invocation, never saved/default config.
  for (const name of ['network', 'rpc']) {
    if (result[name] === undefined && program.getOptionValueSource(name) === 'cli') result[name] = program.getOptionValue(name);
    requireValue(typeof result[name] === 'string' && result[name].length > 0, 'Provide explicit --network and --rpc for Vortex online commands.');
  }
  return result;
}
function ctx(options: any) {
  const c = loadVortex(options.manifest, options.abi, options.review, options.reviewKey);
  if (options.network !== undefined) requireValue(options.network === c.manifest.network.name && options.contract === c.manifest.contract.address, 'Explicit network/contract does not match the manifest.'); return c;
}
function outcome(result: any): void {
  output(result);
  if (result.status !== 'irreversible-and-state-verified') process.exitCode = result.status === 'reverted' ? 1 : 3;
}
export function registerVortexCommands(program: Command): void {
  const wallets = program.command('wallets').description('Separate named encrypted wallets (legacy wallet/config unchanged)');
  wallets.command('create <name>').option('--vault-dir <directory>', 'Private named-wallet directory').action(guarded(async (name, options) => {
    const store = new NamedWallets(options.vaultDir); const password = await newPassword(); output(store.save(randomSigner(), name, password));
  }));
  wallets.command('import <name>').option('--vault-dir <directory>', 'Private named-wallet directory').action(guarded(async (name, options) => {
    const key = await hiddenInput('Import WIF (hidden): '); let signer: Signer;
    try { signer = Signer.fromWif(key); } catch { throw new RefusalError('Invalid import input.'); }
    output(new NamedWallets(options.vaultDir).save(signer, name, await newPassword()));
  }));
  wallets.command('list').option('--vault-dir <directory>', 'Private named-wallet directory').action(guarded(options => output(new NamedWallets(options.vaultDir).list())));
  wallets.command('inspect <name>').option('--vault-dir <directory>', 'Private named-wallet directory').action(guarded((name, options) => output(new NamedWallets(options.vaultDir).metadata(name))));

  const vortex = program.command('vortex').description('Reviewed Koinos Vortex V2 administration; detached signing only');
  online(bind(vortex.command('prepare <action>').description('Prepare one supported action; never unlock, sign or broadcast')))
    .requiredOption('--args <file>', 'Public action arguments as strict JSON')
    .requiredOption('--rc-limit <units>', 'Exact positive raw Mana limit')
    .option('--propose', 'Schedule unpause or validator recovery instead of executing')
    .option('--out <file>', 'Write a new private package; refuse overwrite')
    .option('--dry-run', 'Only display the unsigned package; never write it')
    .action(guarded(async (action, options) => {
      options = explicitOnline(options, program);
      const c = ctx(options); const p = vortexProvider(c, options.rpc, options.corroboratingRpc); const args = strictJson(readSafe(options.args));
      const pkg = await prepareVortex(c, p, await encodeAction(c, action, args, !!options.propose), options.rcLimit);
      output(await reviewPackage(c, pkg));
      if (options.dryRun) { output({ dryRun: true, walletUnlocked: false, signed: false, submitted: false, transaction: pkg.transaction }); return; }
      requireValue(options.out, 'Provide --out or --dry-run.'); writeExclusive(options.out, pkg);
    }));
  bind(vortex.command('inspect <package>')).action(guarded(async (file, options) => output(await reviewPackage(ctx(options), readPackage(file)))));
  for (const role of ['admin', 'payer'] as const) {
    bind(vortex.command(role === 'admin' ? 'sign <package>' : 'payer-sign <package>'))
      .requiredOption('--wallet <name>', 'Explicit named encrypted wallet')
      .requiredOption('--signer <address>', 'Expected public signing identity')
      .requiredOption('--id <transaction-id>', 'Explicit confirmation of the reviewed ID')
      .option('--vault-dir <directory>', 'Private named-wallet directory')
      .option('--out <file>', 'New signed package; inputs are never modified')
      .option('--dry-run', 'Review only; no wallet access/unlock/signature')
      .action(guarded(async (file, options) => {
        const c = ctx(options); const pkg = readPackage(file); const review = await reviewPackage(c, pkg); output(review);
        requireValue(options.id === review.id, 'Confirm the exact reviewed transaction ID.');
        requireValue(role === 'admin' ? review.admins.includes(options.signer) : options.signer === c.manifest.policy.payer, 'Wrong requested signing identity.');
        requireValue(!review.signers.includes(options.signer), 'This identity has already signed.');
        if (role === 'payer') requireValue(review.adminSignatures >= review.required, 'Administrator quorum is required before the separate payer-sign step.');
        if (options.dryRun) { output({ dryRun: true, walletUnlocked: false, signed: false, submitted: false }); return; }
        requireValue(options.out, 'Provide a new --out path.'); const store = new NamedWallets(options.vaultDir);
        requireValue(store.metadata(options.wallet).address === options.signer, 'Selected wallet does not match the requested signer.');
        const signer = store.unlock(options.wallet, await hiddenInput('Wallet password: '));
        const signed = await appendSignature(c, pkg, signer, options.id, role); writeExclusive(options.out, signed); output(await reviewPackage(c, signed));
      }));
  }
  bind(vortex.command('merge <packages...>')).requiredOption('--out <file>', 'New output file').action(guarded(async (files, options) => {
    const c = ctx(options); const merged = await mergePackages(c, files.map(readPackage)); writeExclusive(options.out, merged); output(await reviewPackage(c, merged));
  }));
  online(bind(vortex.command('submit <package>'))).option('--id <transaction-id>', 'Explicit submission confirmation')
    .option('--journal-dir <directory>', 'Existing private submission-intent directory')
    .option('--wait <seconds>', 'Wait for irreversible state verification, 1-300 seconds', '90')
    .option('--dry-run', 'Preflight only; no submission intent or RPC broadcast')
    .action(guarded(async (file, options) => {
      options = explicitOnline(options, program);
      const c = ctx(options); const p = vortexProvider(c, options.rpc, options.corroboratingRpc); const pkg = readPackage(file); output(await preflightVortex(c, p, pkg));
      if (options.dryRun) { output({ dryRun: true, signed: false, submitted: false }); return; }
      requireValue(options.id && options.journalDir && /^[1-9]\d{0,2}$/.test(options.wait) && Number(options.wait) <= 300, 'Submission requires --id, --journal-dir and a bounded wait.');
      outcome(await submitVortex(c, p, pkg, options.journalDir, options.id, Number(options.wait) * 1000));
    }));
  online(bind(vortex.command('reconcile <package>'))).action(guarded(async (file, options) => {
    options = explicitOnline(options, program);
    const c = ctx(options); outcome(await reconcileVortex(c, vortexProvider(c, options.rpc, options.corroboratingRpc), readPackage(file)));
  }));
}
