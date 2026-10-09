# Local Vortex CLI Evidence

The two 4 October 2026 JSON records are actual disposable Koinos-chain runs
through the installed `kcli`, not synthetic RPC fixtures. Each passed 18
acceptance checks. The second also records explicit installed reconciliation,
canonical blocks/heights and resulting-state digests for six authorized actions.

The run uses new synthetic encrypted wallets, a separate payer, 2-of-3 ordinary
administration and 3-of-3 recovery. The contract is the explicitly reviewed
fresh-initializer derivative of the requested Vortex pin; exact source, Wasm,
ABI and patch digests are in each record. A full 48-hour delay and 24-hour
execution window are retained. No public network, real owner, independent
custody, Ethereum administration or deployment approval is represented.

The controlled local chain starts in the past and advances its timestamps while
retaining the real node's future-time guard. This proves contract timing rules,
not 48 hours of wall-clock operation. It holds a stable head for preflight and
mines explicit submissions through LIB; busy-chain availability is not proven.

These records omit wallets, passwords, key material, account identities, RPC
endpoints and access details. Private synthetic packages/volumes and failed-run
diagnostics are retained separately. Do not substitute passing unit tests for
these actual contract-execution records, or treat this evidence as production
readiness. See `../VORTEX_IMPLEMENTATION_STATUS.md` and the administrator guide.

# Local Multisig Treasury Evidence (8 October 2026)

`2026-10-08-multisig-contract-local.json` and `2026-10-08-multisig-cli-local.json` are actual disposable
Koinos-chain runs, not RPC fixtures (local exercises, not a qualification). The first exercises contract
template 1.0.0 with an independent koilib
client (signer subsets, identity counting, single-key and quorum bypass attempts, replay, rotation, the
15-owner bound, address/chain binding and the two reproduced bootstrap attacks), checking every refusal for
its expected reason. The second runs the installed `kcli multisig` workflow end to end with synthetic members
in separate HOME directories and includes an independent check of the CLI bootstrap and of single-key
refusals. Synthetic addresses are redacted; keys, passwords and endpoints are omitted. Each record binds the
source it ran against: the base commit plus a SHA-256 over every tracked and non-ignored untracked file of the working tree
(evidence outputs excluded), with the full per-file manifest. No public network, real owner,
independent custody, external review or deployment approval is represented. See
`../MULTISIG_IMPLEMENTATION_STATUS.md`.

# Testnet Multisig Treasury Rehearsal (9 October 2026)

`2026-10-09-multisig-testnet.json` records one run of the installed `kcli multisig` workflow on the official
Koinos testnet with test-only tKOIN and synthetic members in separate HOME directories on one machine:
reproducible build, bootstrap and verification at an irreversible block, an independent koilib check of the
bootstrap and of single-key refusals, a 3-of-5 payment, rotation by the old quorum and a payment by the new
quorum. Transaction IDs and the treasury address are public testnet data; keys and passwords are omitted. The
record binds the working tree it ran against: base commit plus a SHA-256 over the tracked and non-ignored untracked
files (the generated multisig evidence records and `evidence/README.md` excluded), with the per-file manifest. "Independent" in step
names means distinct member keys in separate HOME directories, all on one machine, not independent custody. It is a
rehearsal, not a qualification: no real owner, independent custody, external review or Mainnet approval is
represented.
