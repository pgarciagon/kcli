# Koinos multisig treasury contract (template 1.0.0)

Status: development template for the proposed kcli multisig workflow. Not audited, not deployed, not qualified
for Mainnet funds. Local-chain evidence does not establish independent custody or Mainnet readiness.

## What it enforces

One Koinos account whose authority is an immutable contract:

| Authority | Rule |
| --- | --- |
| `contract_upload` | Always refused. Code, ABI and the three override flags can never change after the bootstrap upload. |
| `transaction_application` | Bound chain ID, `payer` = treasury, no `payee`, exactly one operation, which must be an allowed KOIN transfer or `set_policy`; current owner quorum. |
| `contract_call` | Only the pinned KOIN contract, `transfer` called directly by that single operation (no nested caller), arguments identical to the operation; current owner quorum. `approve`, `burn`, other contracts and nested calls are refused. KOIN allowances that already existed before the upload are honoured by KOIN without asking the contract and must be ruled out at deployment (see below). |

Allowed KOIN transfer: canonical KCS-4 arguments, `from` = treasury, valid checksummed `to` ≠ treasury,
`value` > 0, empty memo.

Quorum: every transaction signature must recover to a distinct current owner and at least `threshold` of them
must be present. Duplicates, non-owners and extra signatures refuse the transaction. Identities are counted,
never signatures or files.

Policy: 3–15 valid owner addresses in strictly ascending byte order, none equal to the treasury; threshold ≥ 2,
greater than half the owners and below the owner count. `set_policy` replaces the whole policy atomically, checks
the *current* quorum itself (it never calls `checkAuthority` on its own account), bumps `version` and emits
`treasury.policy_updated`.

Every artifact is personalized at build time (no initializer): chain ID, treasury address, KOIN contract,
initial owners and threshold are compiled in (`assembly/Deployment.ts`, rendered from public inputs). The
artifact authorizes nothing at any other address or on any other chain. The checked-in placeholder has no
owners and a zero treasury address, so an unpersonalized build authorizes nothing.

Read methods: `get_policy` (owners, threshold, version) and `get_template` (name, version, chain ID, KOIN
contract, owner bounds).

## Not enforced (by design in v1)

No expiry, cancellation, timelock, spending limit, emergency recovery or upgrade. Other assets (VHP, KCS-4
tokens, NFTs) sent to the treasury cannot be moved by it. Policy rotation consumes one nonce but does not
invalidate signatures of owners who remain eligible. Losing the quorum makes the funds permanently inaccessible.

## Bootstrap requirements (contract cannot enforce these)

Before its upload the treasury address is an ordinary key. State that key creates before the upload survives it:

1. **KOIN allowances.** `approve(treasury, spender, …)` made by the key before the upload is honoured by KOIN
   afterwards without asking the contract. → After deployment the treasury must have **no KOIN allowances**.
2. **Contract storage.** A helper contract (or an earlier, differently configured upload) at the address can seed
   a policy object. → After deployment the policy space must be **empty** and `get_policy` must return the
   embedded initial policy with version `0`.
3. **Koinos Fund votes.** Votes cast by the key before the upload would keep steering the treasury's KOIN weight.
   → On networks with a fund contract the treasury must have **no fund votes**.
4. Use a freshly generated key used for nothing else, a bootstrap transaction with exactly one operation (the
   upload, all three override flags set, `payer` = treasury, no `payee`). Before the upload the address only
   receives a minimal, separately authorized amount of KOIN for the upload's Mana; community funds come only
   after the checks below pass on an irreversible block. The treasury nonce must be exactly 1 after the upload: the
   bootstrap was the first transaction the address ever paid for (other address-indexed state created in
   transactions paid by someone else is not revealed by the nonce; hence the explicit state checks).

## Deployment verification checklist

Bytecode SHA-256 = artifact `wasmSha256`; metadata hash matches; `authorizes_call_contract`,
`authorizes_transaction_application` and `authorizes_upload_contract` all true; no object in the treasury's
policy space; `get_policy` = initial policy, version `0`; `get_template` = expected name/version/chain/KOIN;
no KOIN allowances; no fund votes where a fund exists; treasury nonce = 1; the included bootstrap transaction is
re-checked from its block (exact reviewed ID, single upload operation, expected bytecode, all three flags,
`payer` = treasury, no `payee`, receipt not reverted) and is irreversible on the canonical chain. Then prove with an independent client that the address key alone can neither transfer, pay Mana, change
policy nor upload code.

## Implementation notes

- Addresses, chain ID and owners are compiled in as raw bytes; the contract never decodes Base58. The
  local-chain exercise always includes an owner and a treasury address starting with `11` (a leading zero byte).
- The contract reads transaction fields through an 8 KB system buffer (enough for 15 signatures and a 15-owner
  `set_policy`). A treasury-paid transaction whose operations or signatures exceed it is refused by the kernel
  (fail closed), e.g. an upload paid by the treasury; an upload paid by anyone else reaches the
  `contract_upload` rule and is refused there.
- Contract storage written by `Storage.Obj` uses the empty key; a verifier must read `get_object(space, "")`
  (a `get_next_object("")` scan does not return it).

## Reproducible build

`scripts/build.sh <source> <inputs.json> <out>` runs inside a pinned Node 22 builder with protoc 3.21.12 and the
locked dependency tree of `koinos/koinos-contracts-as@4fc33bb` `contracts/koin` (installed with
`--frozen-lockfile --ignore-scripts`). The build refuses unless the toolchain tree and `koinos/options.proto`
match their pinned content hashes, the generated protobuf classes and ABI equal the reviewed copies, entry-point
constants equal `sha256(name)[0:4]`, and two clean builds produce identical bytes. Output: `contract.wasm`,
`treasury.abi`, the rendered `Deployment.ts`, canonical `inputs.json` and `artifact.json` (hashes and toolchain).
`build.sh` is a POSIX `sh` launcher that always replaces the whole environment (`env -i`) and starts the real
build (`build-inner.sh`) with `bash --noprofile --norc -p`, so `NODE_OPTIONS`, `NODE_PATH`, `LD_PRELOAD`, exported
Bash functions and `BASH_ENV` never reach node or protoc; run it directly, not as `bash build.sh`. The
builder image itself (Node, protoc, coreutils) is a trust assumption; the defence against a compromised builder
is independent reproduction of the same `wasmSha256` by reviewers on their own machines.
