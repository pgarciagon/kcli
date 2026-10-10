# kcli 1.7.1

This patch release publishes the previously local KFS compatibility corrections
on top of 1.7.0. The multisig treasury template remains 1.0.0. Local burn fixes
are intentionally excluded; multisig/Vortex behavior and dependencies are unchanged.

## Included Changes

- Mainnet KFS read commands can use a pinned four-method, read-only bundled
  interface when the RPC ABI index has no entry for the exact default contract.
- RPC metadata remains preferred. Other networks/contracts, incompatible
  metadata and RPC failures fail closed. JSON includes `abi_source`; the
  fallback notice goes to stderr. No automatic RPC switching occurs.
- `vote` and `vote --dry-run` still require compatible indexed RPC metadata.
  The bundled read client cannot prepare a vote or expose a write method.
- Fund result decoding preserves valid protobuf-empty votes while rejecting
  missing outer results, malformed payloads/logs and invalid base64. Existing
  allocations and all chain, wallet, balance/Mana and signing checks remain.
- Sixteen additional fund regression tests and an English
  [RPC compatibility guide](FUND_RPC_COMPATIBILITY.md), included in the package.

## Installation And Integrity

Use Node.js 22 and npm. Download `kcli-1.7.1.tgz` and `SHA256SUMS` from the same
[GitHub release](https://github.com/pgarciagon/kcli/releases/tag/v1.7.1).

```bash
shasum -a 256 -c SHA256SUMS
npm install -g ./kcli-1.7.1.tgz
kcli --version
kcli proposals --help
kcli vote --help
```

The asset is a compiled JavaScript/ABI package, not a native executable or
bundled runtime. npm resolves runtime dependencies; use tagged source and
`npm ci` for exact lockfile resolution. No npm registry publication is included.

## Validation And Limits

Release gates include the complete 161-test suite (41 fund tests) on Node
22.12.0 and 23.11.0, a fresh tarball installation and public asset/checksum
verification. Tests use isolated homes, synthetic keys and loopback/simulated
RPCs. Baseline tests reproduced the absent-ABI failure and invalid-response
acceptance; valid protobuf-empty vote preparation already worked in 1.7.0.
No real wallet/password, signed public-chain vote or production service action
is authorized by software publication. Fund inclusion is not irreversible
finality; a real vote/update/removal round trip and external audit remain open.
The existing 1.7.0 multisig qualification limits still apply.

The locked source passes 161/161 on both runtimes with the candidate executable
explicitly checked before each run. A live read-only relay to api.koinos.io
also passes settings, proposal and allocation reads plus unsigned preparation:
21 reads, no attempted writes and no submissions. The absent-index fallback
is validated synthetically, not asserted for that public endpoint. See the
[compatibility guide](FUND_RPC_COMPATIBILITY.md) for provenance and limitations.

## Historical Releases

The following 1.7.0 and 1.6.0 notes are historical; their installation commands
install those old releases, not 1.7.1.

# kcli 1.7.0

This GitHub software release adds the contract-enforced Koinos multisig treasury
workflow from PR #2. The human approved exact head
bc6c1b1aff90080b6416dee9701ecd5e80df1553; it was merged as
35679b75dab724d7c227bab12355d9eb87777445. Contract template version remains
1.0.0. Software publication does not authorize a real treasury deployment,
funding, member custody or Mainnet activation.

## Included Changes

- Immutable, personalized N-of-M KOIN treasury contract: one canonical payment
  or atomic current-quorum owner/threshold replacement; no unilateral key,
  arbitrary calls, allowances, burns, upgrade or recovery mechanism.
- `kcli multisig`: verified bootstrap, read-only information/preparation,
  offline exact-ID inspect/sign/merge with explicit named members, fresh
  preflight, durable one-shot submission and read-only reconciliation.
- Finality correction: canonical reversible inclusion remains pending; both
  reviewed RPC irreversible heights must cover the transaction block for final
  success/reversion. Exact body, signatures, receipt/event and final canonical
  rechecks remain mandatory. Bounded deadlines never trigger automatic resend.
- Review follow-ups: enclosing block/receipt anchors, bounded witness-head lag
  and durable first-use journal ancestor entries before any submission.
- English foundation operating guide, status/exit-code documentation and
  sanitized local validation evidence. Both new validation guides are packaged.

## Installation And Integrity

Use Node.js 22 and npm. This is a compiled JavaScript package with runtime ABIs,
not a native executable, bundled runtime or npm-registry publication.

```bash
npm install -g https://github.com/pgarciagon/kcli/releases/download/v1.7.0/kcli-1.7.0.tgz
kcli --version
kcli multisig --help
kcli multisig submit --help
```

Download kcli-1.7.0.tgz and SHA256SUMS from the same release, then verify before
installation:

```bash
shasum -a 256 -c SHA256SUMS
npm install -g ./kcli-1.7.0.tgz
```

Source-build users should clone tag v1.7.0 and run npm ci for exact lockfile
resolution. A tarball consumer resolves declared dependencies from npm; these
are neither bundled nor locked by the asset. Tests invoking kcli must use the
candidate executable on an isolated PATH, not an existing global installation.

## Validation And Limits

The correction passes 145 tests on Node 22.12.0 and Node 23.11.0. A clean
pre-merge tarball install also passes all 145 tests on both runtimes, including
payment/policy/bootstrap pending-finality progression, exits 0/1/3, unchanged
signed bytes, one-shot sends and persistent journal/nonce protection. Release
publication additionally requires repeating complete exact-release-commit and
installed-tarball tests, content/provenance checks and public download integrity.

A fresh read-only agent review resolved three P2 client findings and one P3
test-observer issue, with no open finding in scope. The full contract matrix
(12 grouped checks, all 32 signer subsets) and installed-CLI exercise (9 groups)
passed on two fresh disposable local chains. Independent encoding verifies
bootstrap and single-key bypass refusals. Identical synthetic public inputs
produce byte-identical Wasm/ABI in arm64 and emulated amd64 pinned builders,
with two clean builds each. See [release validation](MULTISIG_RELEASE_VALIDATION.md)
and [finality statuses/exit codes](MULTISIG_FINALITY_FIX.md).

Both builders and local members share one host trust domain; synthetic Mainnet
RPC tests are not independently operated Mainnet witnesses. Historical testnet
evidence is not a new public-chain run. Agent review is not an external security
audit, fsync instrumentation is not a physical power-loss test, and these
results do not qualify Mainnet custody or a foundation treasury. Foundation
policy, independent operators/devices, external security review and explicit
Mainnet activation remain separate gates. Quorum loss is permanent; unsupported
assets are stuck. Read the [operating guide](MULTISIG_TREASURY_GUIDE.md) first.

Fresh dependency audits retain zero critical/high/moderate findings and ten
source / eleven consumer low-severity affected packages propagated from the
existing elliptic advisory. No dependency change is included. Use fresh
authorization for real-chain actions. No real keys, public transactions,
production services, host global install or npm publication were used by the
release preparation. The operator's primary checkout/install was preserved;
its private unrelated burn/fund fixes are not in this release.

## Historical Release

The following 1.6.0 notes and measurements are retained as historical evidence;
their commands install that old release, not 1.7.0.

# kcli 1.6.0

This GitHub software release includes the complete local application feature
set authorized for publication on 7 October 2026. It is not an approval for
production-chain operations, a security audit or a bridge deployment.

## Included Changes

- Koinos Fund System reads and voting: `fund-info`, `proposals`, `proposal`,
  `votes` and `vote`, with pagination, JSON output, allocation checks, unsigned
  dry-runs, explicit confirmation, inclusion receipts and allocation readback.
- Mainnet chain-ID checks in transaction preparation. Official testnet token
  and PoB contract bindings remain separate; saved RPC and selected network
  must agree before signing or submission.
- KOIN/KCS-4 transfer `--nonce` and `--no-wait` controls, plus conservative
  Mana-derived producer-registration RC limits. Skipping the wait does not
  verify inclusion. Callers control explicit nonce sequencing.
- Named encrypted wallets and exact detached Vortex signatures, independent
  merge, separate payer, durable submission intent and explicit reconciliation.
- Restricted Vortex mainnet profiles requiring authenticated manifest review,
  an independently trusted review-key fingerprint and two explicit reviewed
  HTTPS RPCs. Bounded advancing-head checks, canonical receipt/finality and
  protected-state corroboration retain exact signed bodies and refuse automatic
  resend. Existing deployments are eligible only after compatibility checks,
  not categorically excluded by address.
- Dashboard-specific bounded HTTP/HTTPS sessions, staggered per-item caching,
  independent KOIN/VHP results, last-good values with stale age, bounded read
  retries/timeouts, unknown pool status and guarded APY. Default balances/supply
  polling is 30 seconds and pool polling is 600 seconds; screen/activity remains
  five seconds. Other commands' transports are unchanged.
- English guides, synthetic regression fixtures and sanitized dated evidence.
- Compatible dependency patches and a direct ethers v5 `HDNode` import remove
  the unused Ethereum/WebSocket provider dependency without changing the
  Kondor derivation implementation or paths.

## Installation

Use Node.js 22 and npm. The release asset is a compiled JavaScript package with
its runtime ABIs, not a native executable or a bundled Node runtime. npm installs
its declared runtime dependencies. No package-registry publication is implied.

```bash
npm install -g https://github.com/pgarciagon/kcli/releases/download/v1.6.0/kcli-1.6.0.tgz
kcli --version
kcli producer-dashboard --help
kcli vote --help
kcli vortex prepare --help
```

For checksum verification, download `kcli-1.6.0.tgz` and `SHA256SUMS` from the
same GitHub release into one directory, then run:

```bash
shasum -a 256 -c SHA256SUMS
npm install -g ./kcli-1.6.0.tgz
```

To build from the exact release source:

```bash
git clone --branch v1.6.0 --depth 1 https://github.com/pgarciagon/kcli.git
cd kcli
npm ci
npm run build
npm link
npm test
```

Tests that invoke `kcli` need that checkout's executable on PATH. For an isolated
check without changing a global installation:

```bash
npm run build
chmod +x dist/index.js
mkdir -p .release-test-bin
ln -sf ../dist/index.js .release-test-bin/kcli
PATH="$PWD/.release-test-bin:$PATH" npm test
```

`npm pack` builds first. The package's explicit file allowlist excludes local
agent notes, memory, default wallets/configuration and password files. Release
assets must be generated from a clean export of the committed release tree,
not the live operator workspace. Runtime dependencies are not bundled or
version-locked by an npm tarball installation; use the committed lockfile and
`npm ci` when exact development dependency resolution is required.

## Validation And Limits

The release is validated with synthetic keys, isolated homes and loopback RPCs.
The full suite contains 104 tests: 25 dashboard, 25 KFS, 29 wallet/local-Vortex,
15 synthetic mainnet-Vortex, eight transfer/producer regression cases and two
Kondor derivation compatibility cases using a public BIP-39 test vector.
No real wallet, public transaction, production node or bridge is operated by
release preparation. Dependency installation, clean compilation, all regression
tests, packed-file review, isolated tarball installation and downloaded-asset
integrity must pass before publication is reported complete.

The dashboard's matched simulator comparison reduced contract reads from 64
to 14 (78.13%) and all RPC calls from 76 to 27 (64.47%); session-limit errors
fell from 26 to zero. This is simulator evidence, not a production benchmark.
The short live comparison had unequal successful rounds and establishes no
live reduction percentage. Cache values and APY are not atomic/head-anchored.
Other clients can still saturate a four-session node. Constrained live HTTPS
qualification remains pending. See [dashboard validation](DASHBOARD_RPC_RELIABILITY.md).

KFS public-chain vote/update/removal execution and a verified official-testnet
fund deployment remain unverified. Vortex mainnet tests use synthetic routing;
the earlier 18-check local-chain exercises are dated acceptance records, not
new release-time executions or public-chain qualification. No compatible
approved mainnet target, independent public RPC pair, real custody or 48-hour
wall-clock exercise is established. See [Vortex status](VORTEX_IMPLEMENTATION_STATUS.md).

Always obtain fresh authorization for an exact real signing/submission action.
Publishing this software does not authorize transfers, burns, votes, bridge
administration, deployments, funding, membership or server changes.

## Dependency Qualification

The 7 October 2026 `npm audit --omit=dev` baseline reported 20 affected packages:
one critical, one high, four moderate and 14 low. The release lockfile resolves
`protobufjs` 7.6.6, `@protobufjs/utf8` 1.1.2 and `bn.js` 5.2.5/4.12.5. Removing
the unused ethers umbrella dependency also removes `ws` and Ethereum providers;
`@ethersproject/hdnode` 5.8.0 is the identical HDNode implementation previously
re-exported by ethers 5.8.0. Public-address vectors cover the unchanged
`m/44'/659'/<account>'/0/0` derivation.

The resulting audit reports zero critical, high or moderate findings and ten
low-severity affected dependencies, all propagated from the remaining
[`elliptic` advisory](https://github.com/advisories/GHSA-848j-6mx2-7j84).
Auditing a consumer project installed from the tarball reports eleven low
entries because it also counts `kcli` itself as an affected dependent package.
The consumer audit's actual dependency versions match the tested global
tarball installation; there is still only one remaining underlying advisory.
That advisory lists no patched version. The affected transitive packages remain
in the HDNode/legacy hdkey dependency graph; kcli's transaction-signing call
sites use koilib's Signer, not ethers' signing APIs. This is a dependency and
call-site check, not a proof of non-exploitability or an independent security
audit. A crypto-library migration requires separate compatibility review.

Both the committed-lockfile source installation and a fresh installation of
the release tarball must be checked. Tarball installs resolve dependencies at
installation time, so this audit result is a dated observation, not a guarantee
about future registry resolution. See the upstream
[`protobufjs` code-execution advisory](https://github.com/advisories/GHSA-xq3m-2v4x-88gg)
and [`ws` denial-of-service advisory](https://github.com/advisories/GHSA-96hv-2xvq-fx4p)
for the issues removed during release preparation.
