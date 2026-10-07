# Vortex CLI Implementation Status

Updated 7 October 2026. The [1.6.0 software release](RELEASE_NOTES.md) includes
the restricted mainnet profile and the full local feature set. Deployment
qualification remains separate. The dated records below preserve prior local
acceptance and publication, not a byte-identical claim for the release build.

## Mainnet Extension Goal, 5 October

Pablo explicitly started the saved goal with "Haz el goal". The bounded software
objective is implemented, tested, locally exercised and documented. Schema-1 local manifests
remain compatible. Schema-2 mainnet manifests require an exact Ed25519 review
attestation, an explicitly trusted review-key fingerprint and two reviewed
HTTPS RPCs with distinct hosts/origins/operator identifiers. The second RPC is
read-only. Public testnets remain refused; existing addresses are not vetoed.

Protected code/authority/storage, nonce and sufficient Mana are observed in
bracketed read windows. Advancing heads are accepted only with bounded canonical
receipt/ancestry checks and no protected deltas; both RPCs must agree on state,
common canonical/LIB heights, exact inclusion and receipt outcome. Same-anchor
state roots/time must agree. Different head heights may agree at common heights.
The 48-hour delay, 24-hour window, exact offline signatures, separate payer,
durable intents and no-resend rules remain unchanged. No generic call/force or
verification bypass was added.

These are optimistic checks under reviewed node/receipt trust, not historical
anchored reads, independent cryptographic state proofs or a complete PoB verifier.
The [administrator guide](VORTEX_ADMINISTRATOR_GUIDE.md) documents bounds, clock
assumptions, review authentication and human approval requirements.

The 5 October development checkout passed 69 tests (25 KFS, 29 wallet/local-Vortex, 15 mainnet
fixtures), including installed online/offline mainnet dry-runs with synthetic
RPC routing and no real wallet/configuration/intent writes. The fixtures cover
authenticated review, TLS policy, advancing/lagging heads, protected deltas,
forks/root mismatches, authority/nonce/Mana disagreement, expiry, exact receipt
and signature matching, insufficient finality and uncertain no-resend behavior.
They do not represent public-chain execution or operator independence.

Two fresh-chain repeats each passed 18 actual contract checks; the final repeat
includes nonce/Mana inside the protected read window and six irreversible
action records through installed `kcli`. It exercised quorum refusals, detached
merge with RPC stopped, delayed unpause, immediate pause, 3-of-3 recovery,
cancellation, replay and expired execution. The clock advances locally from the
past; this is not 48 hours of wall-clock monitoring or busy-public-chain availability.
[Final record](evidence/2026-10-05-vortex-local-e2e-mainnet-extension.json).
The prior 4 October evidence is unchanged. Both installed paths report 1.6.0;
this is a minor software capability bump, not a tag, push or registry release.

A public read-only observation found a candidate ABI incompatible with both
reviewed adapters and unavailable raw-Wasm verification. This does not ban its
address or diagnose its implementation version. No approved mainnet deployment,
independent public RPC pair, actual custody or source/code/policy mapping is
qualified. [Observation](evidence/2026-10-05-vortex-public-observation.json).
Real wallets/configuration, unrelated KFS/transfer work and all production hosts
are preserved. No real signing, public submission, deployment or publication
was performed for this goal.

The first attempt failed before chain bootstrap because Docker's automatic
address pools were exhausted. The harness now uses a collision-checked fresh
explicit internal subnet; no old container/network/volume was removed. Only
new task containers were started/stopped. The dedicated lab VM was returned
to its initial stopped state, and the default Docker context stayed unchanged.

## Prior Local Acceptance And Publication

The earlier local definition of done was achieved; this was not
production qualification or deployment authorization. The user authorized
committing and pushing the completed wallet/Vortex source on 5 October.
This is source publication, not a tagged release or registry publication.
No real keys, mainnet/public-testnet transactions, production membership or
servers were used.

## Parallel Development Scope, 5 October

Pablo clarified that kcli and the bridge are to be developed in parallel and
requested removal of the categorical existing-bridge prohibition. The fixed
address veto was removed locally; existing and fresh deployments must instead
meet the same reviewed code/ABI, authority, membership and policy checks.
This uncommitted change does not establish compatibility with any deployment.
At that decision checkpoint the local-network/loopback guards remained; the
newer mainnet implementation above supersedes that software limitation.

The [updated mainnet goal prompt](VORTEX_MAINNET_GOAL_PROMPT.md) includes parallel
development and read-only qualification of existing deployments, rather than
excluding them by address. It does not authorize real keys, deployment, signing,
transactions, funds, servers or publication. Historical acceptance counts below
describe the earlier revision; the address-policy change has its own regression.
The updated full checkout passes 54 tests (25 KFS, 29 wallet/Vortex), including
formerly excluded address eligibility and installed-CLI public-network refusal.
The local installed build was rebuilt; this revision is not the published
`0be1442` artifact. No disposable-chain rerun or live deployment qualification
is claimed for this narrowly scoped policy change.

## Implemented Locally

- Named encrypted wallets with hidden creation/import/unlock, authenticated
  metadata, bounded scrypt/AES-GCM, protected paths/permissions, exclusive atomic
  writes and key/address verification. Legacy default wallet/config unchanged.
- Restricted exact preparation/inspection, independent transaction ID/root
  recomputation, offline sign-only, separate payer signing and independent merge.
- Policy-selected ordinary/recovery thresholds and separate validator authority;
  immediate pause, unpause/recovery proposal and execution, cancellation only.
- Initially local-only submit with fresh code/ABI/membership/state/nonce/Mana
  checks, durable intent, no automatic retry and canonical receipt/LIB/state
  reconciliation.
- English [administrator guide](VORTEX_ADMINISTRATOR_GUIDE.md), focused tests and
  an opt-in fresh local-chain harness through the installed executable.

## Verification

- Full local checkout `npm test`: 53 passes (25 existing KFS, 28 wallet/Vortex
  tests). The source-publication snapshot includes the 28 wallet/Vortex tests;
  the older KFS and transfer changes remain uncommitted locally.
- On 5 October, the exact staged source was exported to an isolated directory,
  built and tested through its own CLI on a temporary PATH: all 28 tests passed.
  Relative documentation links and both evidence records were checked; no
  private-key or credential literals were found by the scoped pattern scan.
- Installed CLI hidden-input creation/import/cancellation/mismatch and dry-run
  checks passed using isolated synthetic wallets. No secrets appeared in the
  captured output. Both existing global links resolve to this checkout.
- Clean upstream checkout and remote `v2` ref match requested pin
  `42b0ab20653047ec0275c3130accf9210ce4b822`; MIT license inspected.
- Two separate fresh-chain runs passed all 18 acceptance checks through
  native installed `kcli`: hidden creation, prepare/review, independent offline
  sign/merge with RPC stopped, sequential signing, separate payer, explicit
  submit, canonical inclusion/LIB/state verification, delayed unpause,
  immediate pause, 3-of-3 recovery, replay, ordinary cancellation and expiry.
- The actual Wasm contract rejected one admin plus payer, early ordinary and
  recovery execution, two-admin recovery proposal/execution, expired execution
  and replay. These are real disposable-chain results, not mocked RPC results.
- The repeat also passed explicit installed `reconcile` checks and recorded six
  canonical block/height/resulting-state digests for authorized actions.
  [Final evidence](evidence/2026-10-04-vortex-local-e2e.json) and
  [initial evidence](evidence/2026-10-04-vortex-local-e2e-initial.json) contain
  no keys, passwords, account identities or live endpoints.

The isolated miner advances full 48-hour delays from a past-time origin while
the real node's future-time guard remains enabled. It holds a stable head for
preflight through the bounded Docker relay and mines explicit submissions
through LIB. This does not prove 48 hours of wall-clock monitoring, PoB producer
readiness, independent operators or reliable preflight on a busy public chain.

Integration corrections are covered by focused tests: real binary ABI versus
snake-case descriptor names, empty HEX proposal bytes, protobuf zero defaults,
empty native result fields, contract-scoped read caller context, explicit root
CLI options without saved-config fallback, and omitted empty included call args.
Only that known included-args wire default is normalized; all other body fields,
IDs, operations and signatures must match exactly.

The fresh-deployment test candidate is explicitly a reviewed initializer
derivative, not unmodified upstream migration Wasm. Its 48-hour constant is
unchanged. Candidate Wasm SHA-256:
`d66facf63456ff6b2690d7e6756142008b11d985886d8ce10411864eb6992a49`.
Source `Bridge.ts` SHA-256:
`aeaf0281e986505f400ed24e83a8cc49e193d16e03c13057b828ccfd93070411`.
Initializer patch SHA-256:
`9f999b2b4561af7062247a6bf47a47790f0c5d9cabdf548788651955136dcd72`.

## Delivered

The named-wallet and exact detached-signature workflow, 53 focused tests,
actual local-chain acceptance evidence, English guide, README, project memory
and [Vortex handoff](VORTEX_HANDOFF.md) are delivered. Both installed links point
to this checkout and report `1.5.0`; no relinking or tagged release occurred.
The existing `1.5.0` package metadata and test script are included in this
source publication; no additional version bump was made. Older KFS/transfer
implementation changes and private project-local agent notes are excluded.

Failed attempts were retained as private synthetic diagnostics/volumes. One
older failed run's stopped containers/network were removed to free exhausted
Docker address-pool capacity; its data/evidence were preserved. Only newly
created task containers were operated. The temporary lab was stopped after
verification; no production stack was started.

Independent custody, actual owners/keys, public deployment policy, independent
sources, production security qualification and human-approved deployment remain
separate. Public-chain use was hard-disabled in that prior 1.5.0 qualification
build; the current 1.6.0 profile is described above, not production approval.
