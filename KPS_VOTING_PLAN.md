# Koinos Fund System Voting in kcli

Assessment date: 2026-10-03. Implementation verified locally: 2026-10-04.
Status: first implemented locally in version 1.5.0 and included in the
[1.6.0 software release](RELEASE_NOTES.md); public-chain voting remains
unverified. See README.md for the current command interface. The assessment and
initial implementation result below retain their original dated context.

## Scope and Difficulty

This is a moderate, additive change. Both applications use TypeScript and
`koilib` 9.x, and kcli already provides encrypted wallets, transaction
preparation, confirmations, RPC selection, and inclusion tracking.

The requested KPS integration concerns Koinos Fund System (KFS) project votes.
Protocol-upgrade voting by block producers is a separate integration.

Allow approximately one to two focused development days for the client,
focused tests, documentation, and dry-run verification. An on-chain test also
depends on a verified test deployment and a funded test account. This estimate
does not include creating or deploying a new fund contract.

## Sources and Reuse

Reviewed KPS commit: `74cb27da62414d07ca8d2b46539fbfe885ddfe96`.

- [Voting call](https://github.com/Armana-group/kps/blob/74cb27da62414d07ca8d2b46539fbfe885ddfe96/components/vote-button.tsx)
- [Contract configuration and types](https://github.com/Armana-group/kps/blob/74cb27da62414d07ca8d2b46539fbfe885ddfe96/lib/utils.ts)
- [Fund ABI](https://github.com/Armana-group/kps/blob/74cb27da62414d07ca8d2b46539fbfe885ddfe96/lib/abiKoinosFund.ts)
- [Official fund source](https://github.com/koinos/koinos-contracts-as/blob/4fc33bbe0520a77a89619da1e9e6efe98e7c423c/contracts/fund/assembly/Fund.ts)
- [Canonical mainnet chain ID](https://docs.koinos.io/exchanges/offline-signing/)

KPS identifies mainnet fund contract `1A5BmMqV5jN5zBrdkhQumAfDZBzXLPBeN9`.
It calls `update_vote` with the wallet address as `voter`, the project ID as
`project_id`, and `percentage / 5` as `weight`.

No license file or package license was found in the reviewed KPS tree. Confirm
reuse terms before copying its implementation. A practical implementation can
use KPS as the integration reference, obtain the ABI from chain metadata, and
write the CLI adapter using kcli's existing patterns. Any vendored material
needs explicit provenance and applicable notices; do not assume a root license
and a source-file SPDX header are interchangeable.

## Evidence Gathered

Read-only calls through kcli's installed `koilib` succeeded against
`https://api.koinos.io`:

- Retrieved the deployed ABI with `Contract.fetchAbi()`.
- Read fund settings with `get_global_vars` and a project with `get_project`.
- Listed active projects with `get_projects`, ascending by date from `"0"`.

The KPS-style descending query from an empty cursor returned no projects.
Pagination must use a direction-appropriate initial cursor and preserve the
contract's returned cursor. Test empty pages and unchanged cursors explicitly.

The RPC reported mainnet chain ID
`EiBZK_GGVP0H_fXVAM3j6EAuz3-B-l3ejxRSewi7qIBfSA==`.
This value was subsequently checked against official documentation and added
to the mainnet network definition in version 1.5.0.

No transaction was signed, simulated, or submitted. ABI compatibility and
successful reads do not establish source-to-deployed-bytecode equivalence or
successful voting. The commented testnet address in KPS is not a verified
deployment on the current official testnet.

## Implemented Commands

```bash
kcli fund-info
kcli proposals --status active
kcli proposal <id>
kcli votes [address]
kcli vote <id> --percent 50 --dry-run
kcli vote <id> --percent 50
kcli vote <id> --percent 0
```

`vote` updates an allocation; repeating the allocation renews the vote and zero
removes it. Read commands should offer `--json`. `votes` should default to the
imported wallet's public address, then the configured account, without unlocking
the wallet. A dry-run should also accept an explicit public voter address.

## Implementation Steps

1. Add a small fund client and types in `src/fund.ts`. Use a verified contract
   ID per network, with an explicit `--fund-contract` override for a checked
   custom deployment. Fail clearly when no fund is configured for testnet.
   Fetch the deployed ABI and validate required methods and schemas before use.
   Never invoke a write method while discovering the ABI.
2. Register the read commands in `src/index.ts`. Handle pagination and
   active/upcoming/past status correctly. Preserve monetary and voting totals
   with `BigInt`; calculate dates from raw contract timestamps. Do not copy the
   frontend's arbitrary extra day for expiration.
3. Add vote preparation. Validate a positive uint32 project ID and an integer
   percentage from 0 to 100 in steps of five. Read the project and existing
   allocations; check the resulting total allocation before preparing the
   operation. Account for recorded expired allocations as the contract does.
   Check project-status restrictions against the authoritative contract behavior.
4. Add signing and submission using the existing wallet flow. Verify chain ID
   and RPC agreement before unlocking or signing. Show the voter, RPC, network,
   contract, project title, old/new allocation, allocation total, RC limit, and
   unsigned operation. Require `VOTE` confirmation. Support `--password-file`
   and `--yes` consistently with existing transaction commands.
5. Wait for inclusion, then read the user's vote again to verify the new weight
   or removal. Report submission, inclusion, and readback separately. A timeout
   must not imply failure or trigger an automatic resend.
6. Add focused tests and README examples. After implementation passes its
   checks, bump package and documented versions from `1.4.0` to `1.5.0` because
   this introduces new commands. Update project memory with actual validation.

`--dry-run` prepares and displays an unsigned transaction. It must not request a
password, sign, or submit, and does not prove that contract execution will pass.
Only `update_vote` belongs in this write scope; proposal submission and fund
administration are separate features.

## Acceptance Criteria

- Reads work without a private key or password, including pagination.
- Invalid IDs, percentages, excess allocations, and unsupported project states
  fail before signing. Existing allocations are replaced rather than added twice.
- Removing a vote and renewing an unchanged allocation produce the right call.
- Wrong-chain RPCs and unconfigured testnet deployments fail before unlock.
- Dry-runs cannot call signing or submission methods; error paths exit nonzero.
- Large token totals and raw expiration timestamps retain their precision.
- RPC failures and inclusion timeouts do not produce a false success report.
- Build and isolated-config CLI checks pass without modifying user settings.
- A verified test deployment supports an authorized vote/update/removal round
  trip, checked through receipts and state reads. Until then, report on-chain
  voting as unverified. A mainnet vote needs separate exact authorization.

## Implementation Result

All five commands are implemented locally. The build and 25 focused tests pass,
including synthetic signed voting and guarded failure paths. Live mainnet reads
and unsigned vote preparation also pass. Existing global links resolve to this
checkout and report version 1.5.0. No commit, push, public-chain vote, or testnet
deployment was performed.

The deployed ABI required local address/uint64 display annotations after wire
schema validation. Descending pagination required a numeric upper cursor
(27 nines); a text sentinel returned no projects. Both lessons are included in
the client and its tests. A real-chain voting round trip remains an explicit
acceptance gap until an authorized test deployment/account is available.
