# Vortex V2 Koinos CLI Handoff

Updated 5 October 2026. Local implementation and qualification complete;
source-only development work, not a tagged release. The user authorized
committing and pushing the wallet/Vortex source on 5 October. This handoff is
documentation, not signing, deployment,
membership-change or production-operation authorization.

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

This build hard-disables public-chain Vortex use. Do not remove that boundary
or start the mainnet experiment based on this handoff.

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
