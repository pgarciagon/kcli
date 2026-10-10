# Multisig Treasury Operating Guide

Software version: kcli 1.7.1. The `kcli multisig` commands below are
implemented and were exercised end to end on disposable local Koinos chains and
once on the official testnet with synthetic test-only members (see
[implementation status](MULTISIG_IMPLEMENTATION_STATUS.md)). No foundation treasury, real member custody or
Mainnet readiness is established by this guide. Do not fund a wallet on the
strength of documentation alone.

Contract: [contracts/multisig-treasury](contracts/multisig-treasury/README.md) (template 1.0.0).

## 1. What the treasury is

One Koinos account whose authority is an immutable contract. It can do exactly two things, and only with a
quorum of distinct current owners signing the exact transaction:

- one KOIN transfer from the treasury (positive amount, valid recipient, no memo), or
- replace its complete owner set and threshold (`set_policy`).

The treasury pays its own Mana and its nonce orders all operations. It cannot approve allowances, burn,
call other contracts, batch operations, accept a payee or replace its code. Other assets sent to it are
stuck. There is no expiry, cancellation, timelock, spending limit, recovery key or upgrade. If the quorum
is lost, the funds are lost.

Policy rules (enforced by the contract and mirrored by kcli): 3–15 owners; threshold at least 2, more than
half of the owners and below the owner count (one owner may be unavailable). Example: 3-of-5.

## 2. Governance before setup

The foundation adopts a written policy first: public member addresses and how each member's identity and
address were verified; independent devices and backups per member; threshold; who requests, coordinates,
approves, submits and reconciles payments; recipient verification; staged funding limits; lost- or
compromised-key procedure; and acceptance that quorum loss is permanent. Five wallets on one laptop are not
five custodians. Keys, passwords and backups are never recorded in that document, sent to a coordinator,
pasted into an issue or chat, or given to an agent.

## 3. Setup ceremony

Run every command below from a private working directory (`mkdir -m 700 treasury-work && cd treasury-work`):
kcli writes packages and manifests only into directories that are not accessible by group or others, and
never overwrites an existing file. Members do the same on their own devices.

1. **Verify the software.** Check the release checksum, `type -a kcli` and `kcli --version`.
2. **Members create keys on their own devices**: `kcli wallets create member-a` (hidden password prompt).
   Only public addresses are exchanged, verified through a second channel. Two names for one key are one
   signer.
3. **Create a fresh treasury address key** used for nothing else: `kcli wallets create treasury-bootstrap`.
   Do not use it for any transaction, approval or vote before the upload (see §4, why).
4. **Build the personalized contract reproducibly** (`contracts/multisig-treasury/scripts/build.sh`) from
   public inputs: network, chain ID, KOIN contract, treasury address, owners (ascending byte order),
   threshold. At least one independent reviewer rebuilds and must obtain the same `wasmSha256`.
5. **Provision upload Mana**: send a small, separately authorized amount of KOIN to the treasury address
   (the upload is paid by the treasury address itself; no sponsor is involved).
6. **Prepare, inspect, sign and submit the bootstrap** (exactly one upload operation, all three authority
   flags, nonce 1):

   ```bash
   kcli multisig prepare-deploy --artifact ./artifact --network local --rpc http://127.0.0.1:8080/ \
     --rc-limit 100000000 --out deploy.json
   kcli multisig inspect-deploy deploy.json
   kcli multisig sign-deploy deploy.json --wallet treasury-bootstrap --signer TREASURY_ADDRESS \
     --id REVIEWED_BOOTSTRAP_ID --out deploy.signed.json
   kcli multisig submit-deploy deploy.signed.json --network local --rpc http://127.0.0.1:8080/ --dry-run
   kcli multisig submit-deploy deploy.signed.json --network local --rpc http://127.0.0.1:8080/ \
     --id REVIEWED_BOOTSTRAP_ID --wait 300
   ```

   `prepare-deploy` and `submit-deploy` refuse an address that already paid for a transaction, has a
   contract or contract storage, KOIN allowances or (where a Fund contract is bound) Fund votes.
   `submit-deploy` keeps waiting through canonical reversible inclusion, including a reversible reversion.
   On Mainnet, both reviewed RPCs must report the bootstrap block irreversible before `irreversible`
   (exit 0) or `reverted` (exit 1). A pending result at the deadline is exit 3, not permission to resend.
7. **Verify the deployment and write the manifest** (only on an irreversible block):

   ```bash
   kcli multisig verify-deployment deploy.signed.json --network local --rpc http://127.0.0.1:8080/ \
     --manifest-out treasury.json
   ```

   The checks are read at one block, and the command then waits (`--wait`, default 300 s) until that block is
   irreversible, so state seen only at a reversible head cannot pass. Status `deployment-verified` means every
   on-chain check passed: exact included bootstrap body, code and
   metadata hash, the three flags, empty policy storage (including the empty key), the embedded initial
   policy at version 0, treasury nonce 1 and no KOIN allowances (exit 0). `refused` lists the failed checks and
   `reverted` means the upload failed (exit 1); `included-not-irreversible`, `included-reverted`, `unknown` and
   `observation-not-irreversible` (all checks passed, but at a block that is not yet irreversible) are not final
   (exit 3, run it again later). Only `deployment-verified` writes a manifest. Never publish or
   fund an address without it.
   If the bootstrap itself is still reversible, the command returns immediately with a pending status;
   its `--wait` applies to observation-block finality after bootstrap finality is established. On Mainnet,
   both RPCs must finalize the bootstrap and every checklist observation anchor before a manifest is written.
8. **Independent review.** A reviewer reproduces the build, repeats the negative checks with a different
   client (the address key alone cannot transfer, pay Mana, change policy or upload) and compares the
   manifest. Members compare the manifest's SHA-256 fingerprint through an independent channel; a file from
   the coordinator is not a trust anchor.
9. **Retire the deployment key** after verification. Members complete a backup-restore drill.
10. **Fund in stages**, starting with a small separately authorized amount and a test payment.

## 4. Why the bootstrap is checked so strictly

Before its upload the treasury address is an ordinary key, and some state that key creates survives the
upload. A KOIN allowance granted before the upload lets the spender drain the treasury without any owner,
and a policy object seeded by an earlier upload replaces the owners. Both were reproduced on a local chain
and both are caught by `verify-deployment`. This is why the key must be fresh, the bootstrap must be a single
upload paid by the treasury address with nonce 1, and the manifest is only written after verification.

## 5. Payments

```bash
kcli multisig info --manifest treasury.json --network local --rpc http://127.0.0.1:8080/
kcli multisig prepare-transfer --manifest treasury.json --network local --rpc http://127.0.0.1:8080/ \
  --to RECIPIENT_ADDRESS --amount 12.5 --rc-limit 10000000 --note "invoice 2026-17" --out payment.json
```

`prepare-transfer` reads only: it verifies code, flags, policy, nonce, balance and Mana (a KOIN transfer
spends Mana equal to the amount, plus the RC limit) and refuses KOIN allowances. Amounts are exact decimal
strings with at most 8 decimals. `--note` is a local, **unsigned** label. Keep one pending treasury
transaction at a time.

Each member, on their own device (networking may be off):

```bash
kcli multisig inspect payment.json --manifest treasury.json
kcli multisig sign payment.json --manifest treasury.json --wallet member-a --signer MEMBER_A_ADDRESS \
  --id REVIEWED_TRANSACTION_ID --out payment.member-a.json
```

Compare network, treasury, recipient, amount, raw amount, nonce, RC limit and ID with the approved request
through a separate channel; never approve an ID copied from an unverified message. A wrong wallet, a
non-owner or an already-signed identity is refused before the password prompt. Signed packages are
sensitive: anyone holding a quorum-signed package can submit it, and deleting a file revokes nothing.

Offline review cannot see the treasury's current nonce. Approve only the nonce named in the approved request
(normally the current nonce plus one, as `kcli multisig info` shows): a package with a later nonce has no expiry
and can execute once that nonce is next, as long as its signatures still meet the policy then in force and
balance and Mana suffice. An approved package that should not execute is durably cancelled only by consuming
its nonce with another transaction; a rotation that removes its signers makes it invalid only while that policy
stands. Every signature in a
package must be valid: a single non-owner, duplicate-identity or malformed signature makes the contract refuse
the whole transaction, so merge only packages produced by `kcli multisig sign`.

The coordinator merges, dry-runs, submits once and reconciles:

```bash
kcli multisig merge payment.member-a.json payment.member-b.json payment.member-c.json \
  --manifest treasury.json --out payment.approved.json
kcli multisig submit payment.approved.json --manifest treasury.json --network local \
  --rpc http://127.0.0.1:8080/ --dry-run
kcli multisig submit payment.approved.json --manifest treasury.json --network local \
  --rpc http://127.0.0.1:8080/ --id REVIEWED_TRANSACTION_ID --wait 300
kcli multisig reconcile payment.approved.json --manifest treasury.json --network local \
  --rpc http://127.0.0.1:8080/
```

`submit` repeats every check against fresh chain state, records a private intent and a per-nonce lock under
`~/.kcli/multisig-journal/` **before** the single send, and never resends. That journal protects one HOME on
one machine only: the foundation must name a single submission operator per pending transaction, because a
second coordinator elsewhere could still submit the same or a competing package (the chain nonce then decides
which one executes). Only
`irreversible-and-verified` (exit 0) closes a payment: it requires canonical, irreversible inclusion and a
KOIN transfer event with exactly the reviewed sender, recipient and amount. `included` and
`included-reverted` are not final; `submitted-unconfirmed` and `unknown` (exit 3) mean the outcome is not
known — reconcile again, never rebuild at a new nonce because a request timed out. `reverted` (exit 1) is
final only once irreversible.

On Mainnet, canonical agreement and transaction finality are separate checks. Both reviewed RPCs must
agree on the exact inclusion, signatures, receipt and events; both irreversible heights must cover the
transaction block for a terminal result. Ordinary pending finality keeps `submit --wait` polling until the
wait ends, returning `included` or `included-reverted` with exit 3 if necessary. RPC failures or
contradictory evidence cannot become success: submission readback failures return `submitted-unconfirmed`
(exit 3), while read-only reconciliation refuses invalid evidence (exit 1). The same signed package,
submission intent and nonce lock are retained; reconciliation never submits again.

If the corroborating RPC has not yet reached the transaction block, an otherwise corroborated bounded
head lag is pending evidence: `reconcile` returns `unknown` (exit 3), and submission keeps waiting. If
the lag remains at the deadline it returns `submitted-unconfirmed`, not success or a final reversion.
The journal's directory entries and private intent/nonce files must be synced before broadcast; a
filesystem sync failure refuses the send. Preserve this journal when recovering a coordinator.

## 6. Member changes

```bash
echo '{"owners": ["OWNER_1", "OWNER_2", "OWNER_3", "OWNER_4", "OWNER_5"], "threshold": 3}' > policy.json
kcli multisig prepare-policy --manifest treasury.json --network local --rpc http://127.0.0.1:8080/ \
  --policy policy.json --rc-limit 10000000 --out policy-1.json
# sign by the CURRENT quorum, merge, dry-run, submit as above, then:
kcli multisig reconcile policy-1.approved.json --manifest treasury.json --network local \
  --rpc http://127.0.0.1:8080/ --manifest-out treasury-v1.json
```

The replacement is complete and atomic and needs the current quorum. After verification, distribute the new
manifest (`treasury-v1.json`). `info`, `prepare-*` and `submit` refuse a manifest whose policy no longer
matches the chain; packages prepared under the old manifest cannot be inspected with the new one. Keep old
manifests: `reconcile` of a package uses the manifest it was prepared with. Rotation consumes a nonce but does not cancel signatures of
owners who remain eligible. Never lower the threshold to one; the contract refuses it.

Lost or compromised key: suspend approvals, reconcile every outstanding package, rotate with the remaining
quorum. There is no freeze or admin key. If a quorum may be compromised, multisig alone cannot protect the
funds.

## 7. Options and exit codes

Online commands: `--network` and `--rpc` are always explicit (saved configuration is never used);
`--timeout <seconds>` bounds all reads of one command (default 120, 10–600). `submit` and `submit-deploy`
take `--wait <seconds>` (default 120, 1–600) for irreversible verification; their deadline is `--timeout`
plus `--wait` and `--dry-run` for a preflight
without intent or broadcast. `prepare-*` take `--dry-run` instead of `--out`. `sign` and `sign-deploy` take
`--vault-dir` for a non-default named-wallet directory and `--dry-run` to review without opening a wallet.
Exit codes: 0 completed and verified, 1 refused/invalid/reverted, 3 outcome not (yet) final.

## 8. Testnet and Mainnet

- `--network testnet` accepts only the official testnet chain IDs and one HTTPS RPC. It was rehearsed once
  with synthetic test-only members whose keys were on one machine (bootstrap, payment, rotation, payment by the
  new quorum); that is neither independent custody nor a qualification. The RPC must answer `chain.invoke_system_call`.
- Mainnet needs: an Ed25519 review attestation of the exact manifest (`--review`, `--review-key` with an
  independently trusted fingerprint) for **every** command that takes a manifest, including offline `inspect`,
  `sign` and `merge`; for online commands two independently operated reviewed HTTPS RPCs (`--rpc` and
  `--corroborating-rpc`, both listed in the manifest); for the bootstrap a reviewed `--network-profile`
  (`prepare-deploy`) and a separate bootstrap attestation (`sign-deploy`, `submit-deploy`,
  `verify-deployment`), which never qualifies payments. Do not convert examples by replacing `local` with `mainnet`.

## 9. Recurring checks

Run `kcli multisig info` regularly (code, flags, policy, allowances, balance, Mana, nonce); reconcile pending
journals; rehearse missing-member and lost-key scenarios on test-only wallets; refresh manifests after
rotations and after testnet resets.
