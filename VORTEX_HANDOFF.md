# Vortex V2 Koinos CLI Handoff

Updated 7 October 2026. The restricted mainnet software is included in the
[1.6.0 release](RELEASE_NOTES.md), together with KFS, transfer controls and the
dashboard corrections. Production deployment/custody qualification is pending.
The development checkpoints below remain historical evidence, not release-time
public-chain or independent-custody qualification.

## Current Mainnet Extension

Pablo started the persistent goal with "Haz el goal". The CLI now implements
local schema-1 and mainnet schema-2 profiles. Mainnet requires an exact Ed25519
manifest attestation and independently trusted explicit SPKI fingerprint on
every online/offline command. Two independently reviewed HTTPS RPCs are explicit
and manifest-bound; only the primary can submit. Operator labels and URLs are
review assertions, not automatic proof of independence.

The protected read window includes code/authority/storage, payer nonce and
sufficient Mana. Bounded canonical receipt deltas allow unrelated blocks to
advance. Both RPCs must corroborate state, common canonical/LIB heights and
exact included body/signatures/receipt plus resulting state. All earlier
sign-only, quorum/payer, delay/window, durable-intent and no-resend boundaries
remain. These checks trust reviewed nodes and complete recent receipts; they
are not anchored historical reads or cryptographic state proofs.

The 5 October checkout passed 69 tests: 25 KFS, 29 wallet/local-Vortex, 15 synthetic
mainnet fixtures. Installed mainnet online/offline dry-runs use explicit fixture
routing, not public submissions. Two new real local-chain repeats each passed
18 checks; the final repeat includes nonce/Mana in the protected read window
and records six irreversible authorized actions. The installed links report
1.6.0. At that checkpoint no tag, push or registry release was authorized.
The subsequent 7 October request explicitly includes KFS and transfer work in
the GitHub software release; it does not authorize public-chain operations.

Canonical new evidence: `evidence/2026-10-05-vortex-local-e2e-mainnet-extension.json`
and `evidence/2026-10-05-vortex-public-observation.json` in the kcli project.
The first bootstrap attempt hit Docker pool exhaustion; a fresh explicit
internal subnet resolved it without deleting old resources. New containers
and the dedicated lab VM are stopped; prior evidence/artifacts remain frozen.

No approved compatible mainnet target or independently qualified public RPC
pair is established. A read-only candidate observation did not satisfy either
reviewed ABI adapter and raw code verification was unavailable. No existing
address is categorically excluded; future bridge changes require an explicit
source/code/ABI/policy review and matching CLI regression tests. Do not rewrite
frozen Vortex deployment packages or earlier acceptance records to match.

Real wallets, custody, public operations, funds, membership, deployment/setup,
production hosts and Ethereum administration remain separate human-approved
work. This handoff is documentation, not operation authorization.

## Prior Local Delivery

Local implementation and qualification were completed;
source-only development work, not a tagged release. The user authorized
committing and pushing the wallet/Vortex source on 5 October. This handoff is
documentation, not signing, deployment,
membership-change or production-operation authorization.

## Parallel Development Decision, 5 October

Pablo clarified that the bridge and kcli are to be developed in parallel and
asked to remove the prohibition on administering an existing bridge. The
categorical address veto has been removed from the local kcli source. Do not
restore that exclusion in the mainnet roadmap or require a fresh deployment
solely because a contract already exists. A target must still match reviewed
code/ABI, authorities, members, thresholds, state and exact transaction intent;
existing V1/V2 compatibility is not established by this decision.

At the decision checkpoint, public-network/loopback restrictions remained and
recording it did not start a goal. The explicit later request started the
[mainnet development goal](VORTEX_MAINNET_GOAL_PROMPT.md) implemented above.
This is development-scope authorization, not approval to change an existing
deployment, import real keys, sign, broadcast, spend, deploy or operate servers.
The fresh experiment's asset/custody/deployment constraints are not broadened.

## Available In kcli

- `wallets create/import/list/inspect`: separate named encrypted vaults, hidden
  local TTY secrets, authenticated metadata, bounded scrypt/AES-GCM, protected
  paths/permissions, exclusive atomic writes and decrypted-key/address checks.
- `vortex prepare/inspect`: restricted exact one-call review, independently
  recomputed ID/root, explicit chain/RPC/contract/ABI/manifest and unsigned dry-run.
- `vortex sign/merge/payer-sign`: offline detached signatures, exact-body and
  existing-signature preservation, cryptographic identity checks, explicit ID
  confirmation and a separate payer that never counts toward quorum.
- `vortex submit/reconcile`: fresh code/ABI/authority/membership/nonce/Mana and
  proposal checks, durable exact intent, no automatic resend, canonical receipt,
  LIB and resulting-state verification. Exit 0 requires the final verified state;
  uncertain/included-only outcomes remain nonzero.

Initial supported actions: immediate admin pause, unpause proposal/execution,
validator-set recovery proposal/execution and cancellation by proposal kind.
Validator transfer and pause/veto message authorities remain separate. Arbitrary
calls, uploads, setup/token administration and Ethereum administration are not
provided. Legacy default wallet/config and uncommitted KFS work were preserved.

## Provenance And Evidence

Upstream clean checkout and remote `v2` ref matched
`42b0ab20653047ec0275c3130accf9210ce4b822`. The actual test contract is explicitly
the reviewed fresh-initializer derivative, not unmodified migration bytecode:

| Artifact | SHA-256 |
| --- | --- |
| Wasm (unchanged 48-hour delay) | `d66facf63456ff6b2690d7e6756142008b11d985886d8ce10411864eb6992a49` |
| Bridge source | `aeaf0281e986505f400ed24e83a8cc49e193d16e03c13057b828ccfd93070411` |
| Exact ABI | `0810d36e1130a34a8ebfc16a2bb73f58cc00a65dd102fd7a2516017b619ee234` |
| Initializer patch | `9f999b2b4561af7062247a6bf47a47790f0c5d9cabdf548788651955136dcd72` |

53 focused tests pass in the combined local checkout, including all 25 existing
KFS tests. The exact publication snapshot was separately built and passed all
28 wallet/Vortex tests on 5 October through its own isolated CLI; the older
KFS/transfer implementation changes remain local. Two new disposable
chains each passed 18 acceptance checks through native installed `kcli`:
independent signing/merge with RPC stopped, separate payer, delayed unpause,
immediate pause, 3-of-3 recovery, insufficient-quorum/early/expired/replay
refusals, cancellation and irreversible state verification. The second also
passed explicit installed reconciliation and records canonical block/state
digests for six authorized actions. Source and both installed links report
`1.5.0`. Existing version metadata is included in source publication; no
additional version bump, tag, GitHub release or registry publication was made.

Canonical kcli deliverables:

- `VORTEX_ADMINISTRATOR_GUIDE.md`: actual commands and cross-computer exchange.
- `VORTEX_IMPLEMENTATION_STATUS.md`: measured results and remaining limits.
- `evidence/2026-10-04-vortex-local-e2e.json`: richer final acceptance record.
- `evidence/2026-10-04-vortex-local-e2e-initial.json`: initial full acceptance.
- `tests/vortex-local-e2e.js`: explicit opt-in local harness prerequisites.

The experiment is centralized synthetic custody. Local past-origin timestamp
advancement is not 48 hours of real monitoring or independent producer operation.
Synthetic RPC cases separately cover uncertain submission, reversion, changed
body/signatures, missing receipts and forked inclusion; they are not presented
as malicious public-chain exercises. No private keys, passwords, account
identities, real wallets or live endpoints are included in this handoff.

## Next Separate Exercise

The prior 1.5.0 build hard-disabled public-chain Vortex use. The parallel-development
decision permits implementing a reviewed mainnet profile, including compatible
existing deployments, but not simply bypassing verification or activating an
experiment. No permanent address-based exclusion is part of that scope.

1. Independently review the CLI, KDF/TTY/file threat model, dependencies and final
   reproducible contract/CLI artifacts. Authenticate policy/ABI distribution.
2. Review actual owner/device/recovery custody and independently controlled
   administration; three wallets held by one person are not decentralization.
3. Specify a separately authorized network policy, independent RPC/finality
   corroboration, busy-chain preflight behavior, fee funding and restoration.
4. Qualify any required setup/token/validator-message commands against the exact
   candidate before approving them; there is no generic bypass here.
5. Obtain explicit current human approval for each real key, signer, deployment
   and submitted action. Local implementation authorization does not grant it.

The 4 October implementation exercise made no commit or push; source publication
was separately authorized on 5 October. No real-key import, public-chain
transaction, production membership/server change or Ethereum operation occurred.
