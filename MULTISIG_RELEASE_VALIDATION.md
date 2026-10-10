# Multisig Release Validation

Date: 10 October 2026. Target: kcli 1.7.0; treasury template remains 1.0.0.
PR #2 started at 00813ff8ba6806836acdd9f231a9cd3de0736f20 against
29d182d4843c49b09bb99040a2638e44054f84ad. The finality correction and review
follow-ups are described in [MULTISIG_FINALITY_FIX.md](MULTISIG_FINALITY_FIX.md).

## Current Evidence

- Locked dependencies installed with npm ci. Full suite: 145 passing, zero
  failing tests on Node 22.12.0 and Node 23.11.0, using private disposable HOMEs
  and an isolated PATH. Both rebuild TypeScript. Existing punycode/multibase
  dependency warnings remain; no dependency upgrade is included.
- A fresh read-only agent reviewed the contract, client, supporting helpers and
  regression tests independently of the implementation context. Three P2
  client findings were resolved, then re-reviewed with no blocking production
  finding. A P3 test-observer issue was also fixed. This is an agent code review,
  not an external security audit.
- New isolated Colima engine, no host-directory mounts or context activation.
  Existing Docker Desktop, Vortex, Teleno and production resources were not
  started or operated. Only new namespaced resources and synthetic keys are used.
- Separate arm64 and amd64 builders start from the same digest-pinned Node 22
  image and frozen koinos-contracts-as dependency lock at
  4fc33bbe0520a77a89619da1e9e6efe98e7c423c. Both toolchain trees match
  e5289f1f492a33c4f6d22ae5eef49df1f9041c58f9d5990922855aeda587d9c5.
  Protoc remains 3.21.12 (Debian package revision 3.21.12-3+deb12u1).
- The identical fresh synthetic deployment inputs produced identical Wasm in
  both architectures, with two clean builds per architecture:
  6ffdc24ff65a82a49da67e48479135bace82fdbc942eac58f54bf9f3541a526d
  (56,779 bytes). Generated ABI SHA-256:
  3b2d0b97d355b70db007f72d58c71294275f03f35baa38fcc68d0b1767e46028.
  Both ABI files match the reviewed template. Public inputs differ from the
  historical deployment, so the personalized Wasm is not its historical hash.
- KOIN testnet-variant lab build reproduced its pinned SHA-256:
  4251a6e9d9c9a37f3bbf67e171f63a7dcad62309e4be7d9da85a74f68520edf7.

## Fresh Local Chain Validation

The complete fresh contract matrix passed all 12 grouped checks, including all
32 signer subsets, duplicate/non-owner/excess signatures, single-key authority
bypass refusals, forbidden quorum envelopes and nested calls (with positive
control), replay, rotation, the 15-owner bound, address/chain binding and both
bootstrap attacks. The installed-CLI exercise passed all 9 grouped workflow
steps on a second fresh chain: hidden synthetic wallet import, bootstrap,
irreversible verification, independently encoded bootstrap and bypass checks,
payment, old-quorum rotation and new-quorum payment/reconciliation. The built
candidate was installed only in the disposable container, with its own PATH
and private HOMEs, not globally on the host.

The source fingerprint for src/multisig.ts in the installed candidate matches
the tested source: 108cbf6060e932cb1a8bd955b00e0ac447b0f159c6e2201889a40c143940b690.
[Sanitized evidence](evidence/2026-10-10-multisig-release-validation.json)
contains the fresh results, public synthetic build inputs, cross-architecture
artifacts and source fingerprints; no keys or passwords are included.

No partial run counts as completed evidence. Initial harness setup
attempts were refused by missing/mismatched lab genesis configuration; the chain
guard was not weakened. A local-only nested-call probe fixture was rebuilt for
the current SDK, and a missing entrypoint invocation was caught by its positive
control before repeating the matrix. None of these attempts used a public chain.

## Publication Gate

Publication requires verified scoped push, approval to merge the exact reviewed
SHA, then version synchronization, release-candidate suite/pack inspection,
isolated tarball installation, checksums and independently verified GitHub asset
downloads. No release has been published yet.

## Qualification Limits

Both builders run under the same host/Colima trust domain (amd64 is emulated),
not two independent operators. The local chain uses one synthetic producer and
a lab-only name-service stand-in; the RPC witnesses in finality tests are
simulators. Real independently operated Mainnet RPCs, foundation members on
their own custody devices, foundation policy decisions, external security review
and Mainnet operational qualification remain separate gates. Journal fsync
tests instrument ordering; they are not physical crash/power-loss tests.

Software publication does not authorize funding or operating a real treasury.
No real keys/passwords, public-chain transactions, host global installation or
npm registry publication is part of this goal.
