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
