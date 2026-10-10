# Multisig Treasury Implementation Status

Updated 10 October 2026. Implements the plan of issue #1 (foundation treasury multisig) through Phase 3 on
**disposable local chains**, plus one rehearsal on the official testnet with synthetic test-only members on one
machine. Software version: kcli 1.7.0, contract template 1.0.0. Not externally audited,
not deployed on Mainnet, no real custody. Software publication is not treasury activation.

## Prior art

No existing Koinos multisig was found that fits this treasury's requirements (8 October 2026); the contract
here is new.

## Implemented

- **Contract template 1.0.0** (`contracts/multisig-treasury`): immutable authority (upload always refused),
  envelope rules (bound chain, treasury payer, no payee, exactly one operation), canonical KOIN transfer or
  `set_policy` only, quorum of distinct current owners, 3–15 owners, majority threshold below the owner count,
  atomic policy replacement checked against the current quorum, build-time personalization (chain, treasury
  address, KOIN, initial policy) with no initializer. Reproducible build pinned by toolchain content hash.
- **kcli** (`src/multisig*.ts`): `multisig info`, `prepare-deploy`, `inspect-deploy`, `sign-deploy`,
  `submit-deploy`, `verify-deployment`, `prepare-transfer`, `prepare-policy`, `inspect`, `sign`, `merge`,
  `submit`, `reconcile`. Offline commands use no network. Signing needs an explicit named wallet, the
  expected owner address and the exact reviewed ID; wrong identities are refused before unlock. Online
  commands need explicit `--network`/`--rpc`, use a multisig-scoped transport (≤2 sockets and requests per
  endpoint, 10 s wall-clock per request, ≤2 retries for reads only, command deadline) and verify code
  (kernel metadata hash), flags, policy, nonce, balance, Mana and absence of KOIN allowances in anchored read
  windows. Submission writes a canonical private intent and per-nonce lock before one send and never
  resends; reconciliation requires canonical irreversible inclusion plus event or policy readback.
  Mainnet: an attested manifest for every manifest-based command (offline `inspect`, `sign` and `merge`
  included), two corroborated reviewed RPCs for online commands, and for the bootstrap a reviewed network
  profile plus a separate bootstrap attestation (`sign-deploy`, `submit-deploy`, `verify-deployment`).

## Evidence

- Initial PR evidence: `node --test` reported 121 passing (104 before the multisig addition),
  offline, isolated HOMEs, synthetic keys.
- [Contract exercise](evidence/2026-10-08-multisig-contract-local.json) on a fresh local chain with
  official images, KOIN from `koinos-contracts-as@4fc33bb` and Mainnet-like Mana routing, using an independent
  koilib client: all 32 signer subsets of 3-of-5; duplicate, distinct-nonce, high-s, non-owner and excess
  signatures; the address key alone (transfer, approve, upload, Mana, sponsored); quorum misuse (upload,
  approve, burn, batch, mixed, memo, zero, self, bad checksum, other payer, payee, nested contract call with a
  positive control); replay; rotation and stale nonce; 15 owners / threshold 14; address and chain binding;
  both bootstrap attacks reproduced and detected. Every refusal is checked for its expected reason.
- [Installed-CLI exercise](evidence/2026-10-08-multisig-cli-local.json): bootstrap, verification, an
  independent client's check of the canonical bootstrap and of single-key refusals, a 3-of-5 payment by
  members in separate HOME directories with hidden PTY passwords, rotation by the old quorum, a payment by the
  new quorum, stale manifest and removed member refused.
- [Testnet rehearsal](evidence/2026-10-09-multisig-testnet.json) on the official Koinos testnet (9 October 2026,
  test-only tKOIN, synthetic members in separate HOME directories): reproducible personalized build (two identical
  builds), upload Mana measured with `broadcast: false`, bootstrap by the installed CLI at block 9,075,132 verified
  at an irreversible block, an independent koilib check of the bootstrap and of single-key refusals (transfer,
  `set_policy`, upload; nonce and Mana unchanged), a 3-of-5 payment, rotation by the old quorum and a payment by the
  new quorum, each irreversible and reconciled. Upload Mana used ≈4.67 tKOIN (limit 9.33, 10 tKOIN provisioned).
- Measured RC per KOIN transfer: ≈2.5 M (3 signatures), ≈3.3 M (5), ≈7.0 M (14), ≈7.3 M (15); `set_policy`
  ≈2.4–3.2 M. Use these to choose `--rc-limit` with headroom; kcli never changes it after signing.

The local chain is a laboratory: one producer, blocks on demand, a lab-only name-service stub for KOIN's
governance lookup. It proves contract and client behaviour, not network availability or independent custody.

## Implementation notes

- Addresses are compiled into the contract as raw bytes; the contract never decodes Base58. The exercises
  always include addresses starting with `11` (a leading zero byte).
- `Storage.Obj` writes under the empty key, so verification reads `get_object(space, "")` in addition to a
  `get_next_object` scan.
- kcli uses the kernel's contract metadata hash as code identity (reading large bytecode through
  `chain.invoke_system_call` can exceed a node's default return buffer).
- The build derives the ABI from protoc's descriptor set and needs no network access.
- KOIN, as a system contract, keeps balances in a system space with id 1 under its own zone, written in
  practically every block. The multisig read window therefore protects exactly: kernel-zone writes (dispatch,
  the treasury's and KOIN's code/metadata, the treasury nonce), any system-contract storage key starting with the
  treasury address (its KOIN balance and allowances; KOIN's storage zone is not its contract ID) and the
  treasury's own storage.

- `kcli multisig` reads through `chain.invoke_system_call`. A node whose koinos-jsonrpc still loads a descriptor
  set older than the one shipped with koinos/koinos `45e7c6e` answers "unknown method"; the RPC then has to be
  updated first. Newer descriptors also render
  `state_delta_entries` in receipts, which api.koinos.io already does.

## Deviations from the issue plan

- No `payer-sign-deploy`: sponsor-free bootstrap (the treasury address pays its own upload) is sufficient.
- No `--journal-dir`: one canonical journal under `~/.kcli/multisig-journal/` with a per-nonce lock, so a
  second directory cannot sidestep the no-resend rule on one machine.
- `verify-deployment` reports `deployment-verified`, not a qualification; the independent reviewer's build
  reproduction and negative-authority checks remain separate (Mainnet: required before any signing).
- Contract-call authority checks the operation and its arguments directly rather than relying on KOIN's
  `data`; both must agree.

## PR #2 finality correction

The preliminary inclusion check now corroborates the current canonical chain at the common LIB without
requiring the transaction block to be irreversible first. Canonical reversible inclusion is pending, not
a readback error. Both RPCs must still finalize the transaction for terminal success or reversion; exact
body/signature/receipt/event verification, final canonical rechecks, journals, nonce locks and one-shot
submission are unchanged. The correction also applies to bootstrap inclusion and deployment verification.

See [Finality correction validation](MULTISIG_FINALITY_FIX.md) for the regression, isolated CLI checks,
status/exit-code contract and fresh synthetic validation. This does not upgrade the historical chain
evidence above into Mainnet qualification or an independent security audit. Fresh review follow-ups also
bind enclosing block/receipt anchors, preserve waiting during bounded witness head lag, and sync first-use
journal ancestor entries before sending. The full suite passes 145 tests on Node 22 and Node 23.
See [release validation](MULTISIG_RELEASE_VALIDATION.md) for the 1.7.0 validation procedure and evidence.
Contract template 1.0.0 is unchanged. The human approved PR head bc6c1b1 and GitHub merged it as
35679b75dab724d7c227bab12355d9eb87777445 before the isolated release preparation.

## Not done (open gates)

1. Phase 0 decisions by the foundation: roster, threshold, custody domains, owners of the review, release
   and operations roles.
2. Foundation-selected independent operators must reproduce the personalized artifact and review contract
   and client. Release validation has matching arm64/emulated-amd64 builds and an independent agent review
   in one host trust domain; these are not independent custody or an external security audit.
3. Testnet rehearsal by the foundation's actual members on their own devices (the 9 October run used synthetic
   test-only keys on one machine).
4. External security review; residual-risk record.
5. Mainnet activation is a separately authorized go/no-go after the operational gates above. The
   software release procedure and its evidence are recorded in MULTISIG_RELEASE_VALIDATION.md.
