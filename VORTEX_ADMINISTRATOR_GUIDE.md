# Vortex V2 Koinos CLI Administration

Software qualification guide for 1.6.0, updated 7 October 2026. The
[software release](RELEASE_NOTES.md) is not production approval. These commands require neither
Kondor nor an administration website. Ethereum administration is outside scope.

## Boundary And Provenance

The decoder targets `VortexBridge/vortex-bridge-v2` at
`42b0ab20653047ec0275c3130accf9210ce4b822`. Only one top-level bridge call is
supported per transaction. There is no arbitrary-call, batch or code-upload
bypass. Initially supported actions are:

| Action | Authority | Scheduling |
| --- | --- | --- |
| `pause` | Administration threshold | Immediate |
| `unpause --propose` | Administration threshold | Creates a proposal |
| `unpause` | Administration threshold | Consumes the mature proposal; also respects latest-pause delay |
| `recover_validators --propose` | Recovery threshold | Creates a recovery proposal |
| `recover_validators` | Recovery threshold | Consumes the mature recovery proposal |
| `cancel` | Administration or recovery threshold, according to proposal kind | Cancels the exact proposal |

Thresholds and membership come from an independently reviewed deployment policy,
then must match the actual contract. The implementation does not hardcode
2-of-3 or 3-of-3 throughout the workflow. The qualified timing profile is a
48-hour delay and a 24-hour execution window. The pinned contract's setup phase
permits immediate recovery before setup is frozen; the CLI displays that state.

Validator transfer signatures and validator pause/veto messages are different
authorities. This command group deliberately refuses embedded validator
signatures. It does not enroll validators or prove independent custody.

**Local schema-1 profiles retain literal loopback HTTP. Mainnet schema-2 profiles
require authenticated review inputs and two explicit reviewed HTTPS RPCs.**
Public testnets remain unsupported in this command group. Software capability is
not approved custody, a compatible deployment or permission for a real action.

On 5 October Pablo clarified that kcli and the bridge should be developed in
parallel. There is no permanent veto of an existing bridge address: eligibility
must follow reviewed code/ABI, authority and policy compatibility. Removing the
address veto does not establish compatibility or approve any production action.
See the [mainnet development goal](VORTEX_MAINNET_GOAL_PROMPT.md).

## Named Encrypted Wallets

Use a disposable private directory for rehearsal, not your real wallet home:

```bash
LABHOME=$(mktemp -d)
LABHOME=$(cd "$LABHOME" && pwd -P)
chmod 700 "$LABHOME"
HOME="$LABHOME" kcli wallets create admin-a --vault-dir "$LABHOME/wallets"
HOME="$LABHOME" kcli wallets create admin-b --vault-dir "$LABHOME/wallets"
HOME="$LABHOME" kcli wallets create admin-c --vault-dir "$LABHOME/wallets"
HOME="$LABHOME" kcli wallets create fee-payer --vault-dir "$LABHOME/wallets"
HOME="$LABHOME" kcli wallets list --vault-dir "$LABHOME/wallets"
HOME="$LABHOME" kcli wallets inspect admin-a --vault-dir "$LABHOME/wallets"
```

Passwords are entered hidden in the local terminal. New passwords require at
least 12 characters. `wallets import admin-a --vault-dir DIRECTORY` also reads
the WIF hidden; it accepts no secret argument, environment variable or password
file. Never import real administration keys during development. No private key
or recovery phrase is displayed. Cancellation discards queued input before
restoring terminal echo.

Vaults use AES-256-GCM, a random 32-byte salt, a random 12-byte IV, authenticated
public metadata, and scrypt `N=131072, r=8, p=1`. Decryption accepts only that
bounded parameter set and checks the decrypted key against the recorded address.
The scrypt profile follows [OWASP's guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt);
the crypto primitives are provided by [Node.js](https://nodejs.org/api/crypto.html).

Directories must be owned by the operator and mode `0700`; vaults are `0600`.
Unsafe names, symlinks, hard-linked files, unsafe permissions and overwrite
attempts are refused. Writes are synchronized and atomically linked to a new
destination. Existing default `wallet.json`, `config.json` and legacy commands
are not migrated or rewritten. Explicitly selected named wallets are mandatory
for Vortex signing. There is no delete/export command in this workflow.

Back up encrypted vaults separately under an accepted recovery policy. Keep the
unlock password elsewhere, never beside the vault. JavaScript cannot guarantee
erasure of every secret string or prevent a compromised same-user process from
reading memory. This is software-wallet custody, not hardware isolation or a
complete wallet security audit. Losing the vault or password can lose the key.

## Review Inputs

Receive the exact ABI file and a deployment manifest through independently
trusted channels. Inspect their digests and source/build correspondence on each
signing computer. A `reviewed: true` flag is an operator declaration, not proof
of review, deployment or authority. Wallet configuration and public addresses
do not establish contract membership or possession of keys.

Local manifest schema (unchanged):

```json
{
  "schema": 1,
  "source": {
    "repository": "https://github.com/VortexBridge/vortex-bridge-v2",
    "commit": "42b0ab20653047ec0275c3130accf9210ce4b822",
    "variant": "pinned-migration",
    "adapterSha256": null
  },
  "network": { "name": "local", "chainId": "REVIEWED_LOCAL_CHAIN_ID" },
  "contract": {
    "address": "REVIEWED_BRIDGE_ADDRESS",
    "codeSha256": "REVIEWED_WASM_SHA256",
    "abiSha256": "EXACT_ABI_FILE_SHA256"
  },
  "policy": {
    "reviewed": false,
    "admins": ["ADMIN_A", "ADMIN_B", "ADMIN_C"],
    "adminThreshold": 2,
    "recoveryThreshold": 3,
    "validators": ["VALIDATOR_1", "VALIDATOR_2", "VALIDATOR_3"],
    "payer": "SEPARATE_FEE_PAYER",
    "delayMs": "172800000",
    "actionWindowMs": "86400000"
  }
}
```

This is deliberately non-runnable. Bind real **synthetic rehearsal** addresses
and reviewed hashes before using it. A fresh initializer derivative uses
`variant: "fresh-initializer"` and the reviewed adapter patch digest instead of
`null`; it is explicitly not byte-identical to the upstream migration contract.
The contract's exact deployed code hash, three authorization flags, ABI hash,
administrator map, validator map and thresholds are checked against the policy.
When membership changes, review a successor manifest before preparing more
transactions. Do not edit a signed package to follow a new policy.

## Restricted Mainnet Profile

Keep the same source, contract and policy fields, but use `schema: 2` and the
following network fields. This example is deliberately non-runnable; the RPC
operators, endpoints, code/source correspondence and full deployment policy must
be reviewed independently, not inferred from a name or two different URLs.

```json
{
  "name": "mainnet",
  "chainId": "EiBZK_GGVP0H_fXVAM3j6EAuz3-B-l3ejxRSewi7qIBfSA==",
  "rpcs": [
    { "url": "https://REVIEWED_PRIMARY/", "operator": "reviewed-primary-operator" },
    { "url": "https://REVIEWED_WITNESS/", "operator": "reviewed-witness-operator" }
  ]
}
```

The mainnet ID is documented by [Koinos](https://docs.koinos.io/exchanges/offline-signing/).
RPC hostnames, origins and operator identifiers must differ. The human reviewer
must establish actual operator independence and accepted node software/history;
labels alone cannot prove it. Both RPCs must support raw code, authority,
contract-scoped membership reads, metadata and canonical full block receipts.
Endpoints use canonical HTTPS URLs, including a root trailing slash. Credentials,
query strings, fragments, redirects, literal IPs and reserved local hostnames
are refused. TLS certificate validation remains enabled; disabling it through
`NODE_TLS_REJECT_UNAUTHORIZED=0` is refused. No implicit endpoint or saved
network/contract fallback is used.

Distribute a separate public attestation over the **exact manifest file bytes**:

```json
{
  "schema": 1,
  "manifestSha256": "LOWERCASE_SHA256_OF_EXACT_MANIFEST",
  "publicKey": "CANONICAL_BASE64URL_ED25519_SPKI_DER",
  "signature": "CANONICAL_BASE64URL_64_BYTE_ED25519_SIGNATURE"
}
```

The signed UTF-8 payload is `kcli-vortex-manifest-v2`, one newline, then the
64-character manifest digest, with no final newline. The public key is the
44-byte Ed25519 SPKI DER encoding. `--review-key` is its lowercase SHA-256
fingerprint, obtained through an independently trusted channel, not accepted
automatically from the attestation. The review signing key is separate from
Koinos wallet keys and contributes no administration quorum. This CLI verifies
attestations; it does not create a production reviewer identity or manage its
private key. A valid signature authenticates an assertion, not the quality of
the audit or authorization to deploy, sign, spend or submit.

All mainnet commands, including offline inspect/sign/merge/payer-sign, need:

```bash
BIND=(--manifest mainnet-deployment.json --abi bridge.abi \
  --review manifest-review.json --review-key "$TRUSTED_REVIEW_KEY_SHA256")
ONLINE=(--network mainnet --rpc "$REVIEWED_PRIMARY_HTTPS_RPC" \
  --corroborating-rpc "$REVIEWED_WITNESS_HTTPS_RPC" \
  --contract "$REVIEWED_BRIDGE" "${BIND[@]}")
kcli vortex prepare pause "${ONLINE[@]}" --args pause-args.json \
  --rc-limit 300000000 --dry-run
```

The two explicit URLs must be the pair in the authenticated manifest. Only the
primary can submit; the corroborating provider is read-only. Obtain current
human approval for each exact real operation before using the signing/submission
examples below. No approved compatible mainnet deployment is supplied here.

### Advancing-Chain Checks

The [chain RPC schema](https://github.com/koinos/koinos-proto/blob/master/koinos/rpc/chain/chain_rpc.proto)
has head-only state reads, not a block selector. kcli brackets each complete
code/authority/bridge observation with heads. When heads advance, it verifies
canonical ancestry and full receipts across at most 16 blocks and rejects any
delta touching the contract's storage, bytecode/authority metadata, payer nonce
or system-call dispatch. Nonce and sufficient Mana are observed inside the same
bracketed window; nonce is rechecked before sending. Both
nodes must independently return the same protected state; the cross-node
observation interval is checked too. Forks, regressions, missing receipts,
overlong intervals or protected writes refuse the operation without repairing
the signed package. Unrelated writes need not stop a preflight. A trusted local
clock and public heads within 120 seconds are required.

Canonical block IDs are compared at common head and irreversible heights. Final
completion additionally requires both nodes to corroborate the exact transaction
block, transaction body/signatures, receipt outcome, sufficient LIB and the
action-specific resulting state. Payer nonce is checked on both nodes and
rechecked on the primary; each must report sufficient Mana.

These are bounded optimistic checks under reviewed RPC trust, **not** anchored
historical reads, cryptographic state proofs or a full PoB verifier. Complete,
correct recent receipt deltas are a node trust requirement; malicious/incomplete
records and hidden transient forks are not independently proven absent. Later
state changes can make an old transaction's current resulting-state readback
unverifiable, requiring manual history review. Finality checks are corroboration,
not custody or public operational readiness. There is no force/skip/rebuild or
automatic resend option.

## Prepare And Inspect

Create public argument files in your private review directory. `pause` and
`unpause` use `{}`; recovery uses `{"validators":[...]}`; cancellation uses
`{"actionHash":"0x1220..."}`. Amounts/timestamps must remain decimal strings.

```bash
mkdir -m 700 review journal
RPC=http://127.0.0.1:YOUR_LOCAL_PORT
BRIDGE=YOUR_REVIEWED_SYNTHETIC_BRIDGE
BIND=(--manifest deployment.json --abi bridge.abi)
ONLINE=(--network local --rpc "$RPC" --contract "$BRIDGE" "${BIND[@]}")

kcli vortex prepare pause "${ONLINE[@]}" --args pause-args.json \
  --rc-limit 300000000 --dry-run
kcli vortex prepare pause "${ONLINE[@]}" --args pause-args.json \
  --rc-limit 300000000 --out review/pause.json
kcli vortex inspect review/pause.json "${BIND[@]}"
```

Preparation and dry-run never unlock, sign or broadcast. Saved network/RPC
configuration is ignored. Every review displays the chain/contract, decoded
action and nested proposal, transaction ID, all signed header fields, payer,
nonce, Mana limit, authorized administrators, applicable threshold, verified
signers and proposal timing. Snapshots are historical observations, not offline
proof of current authority. Submission obtains fresh evidence.

The transaction ID and operation root are recomputed using an independent,
restricted protobuf encoder and Node SHA-256. Unknown fields, unknown calls,
changed bodies, redirected targets, ABI drift and noncanonical bytes fail closed.
No payee or additional operation is accepted in this initial workflow.

## Detached Signatures

After inspecting the package, set `ID` to the exact displayed transaction ID.
Each signer must review that same ID and decoded action independently. The
`--id` argument is the explicit signing confirmation; there is no `--yes`
shortcut. Passwords are entered only in the local hidden prompt.

Sequential signing:

```bash
kcli vortex sign review/pause.json "${BIND[@]}" \
  --wallet admin-a --vault-dir "$LABHOME/wallets" --signer ADMIN_A_ADDRESS \
  --id "$ID" --out review/pause-a.json
kcli vortex sign review/pause-a.json "${BIND[@]}" \
  --wallet admin-b --vault-dir "$LABHOME/wallets" --signer ADMIN_B_ADDRESS \
  --id "$ID" --out review/pause-ab.json
```

Independent signing and merging:

```bash
kcli vortex sign review/pause.json "${BIND[@]}" \
  --wallet admin-b --vault-dir "$LABHOME/wallets" --signer ADMIN_B_ADDRESS \
  --id "$ID" --out review/pause-b.json
kcli vortex merge review/pause-a.json review/pause-b.json "${BIND[@]}" \
  --out review/pause-merged.json
```

Merge independent branches, not overlapping sequential branches: duplicate
signatures are refused, not silently discarded. Header, operations, ID, policy
binding and review snapshot must be identical. Every signature is recovered and
checked cryptographically. Unknown, duplicate, malformed, noncanonical or wrong
requested identities are refused. Inputs are never overwritten.

Signing requires no RPC. It signs only the already-verified digest, without SDK
preparation, Mana estimation or header rewriting. Valid existing signatures are
retained. `--dry-run` can inspect a signing request without accessing a vault.

## Separate Payer, Submission And Reconciliation

The payer cannot be an administrator or validator and does not increase quorum.
Payer signing is a separate offline step after the applicable admin quorum:

```bash
kcli vortex payer-sign review/pause-merged.json "${BIND[@]}" \
  --wallet fee-payer --vault-dir "$LABHOME/wallets" --signer PAYER_ADDRESS \
  --id "$ID" --out review/pause-ready.json
kcli vortex submit review/pause-ready.json "${ONLINE[@]}" --dry-run
kcli vortex submit review/pause-ready.json "${ONLINE[@]}" \
  --id "$ID" --journal-dir journal --wait 120
kcli vortex reconcile review/pause-ready.json "${ONLINE[@]}"
```

There is no sign-and-submit command. Submission freshly checks chain identity,
code/ABI/authority binding, full membership, thresholds, payer nonce/Mana, epoch,
proposal identity, delay, expiry and replay rules. Any changed reviewed state
requires a new separate review; the CLI never repairs or rebuilds a signed body.

Before sending, an exclusive `0600` submission intent retains the exact package
in the private journal. A second `submit` with that intent is refused. Reconcile
by transaction ID after timeouts, crashes, lost replies or uncertain receipts;
absence from transaction storage alone does not prove that retry is safe.
There is no automatic retry, delete-intent or rebuild-and-resend option.

Reported states distinguish prepared, partially signed, signature requirements
satisfied, submission outcome unknown, included successfully, reverted, and
irreversible with resulting state verified. Exit `0` from submit/reconcile means
the last state; `3` means incomplete/uncertain; `1` means refused/reverted.
An RPC receipt alone is not inclusion. Inclusion alone is not finality. The CLI
checks the canonical block, exact included transaction, block receipt, LIB and
action-specific state/proposal consumption. Local profiles trust one explicit
RPC; mainnet profiles require the independent corroboration described above.

## Recovery And Scheduling

```bash
kcli vortex prepare recover_validators "${ONLINE[@]}" --propose \
  --args recovery-args.json --rc-limit 300000000 --out review/recovery-proposal.json
```

For the experiment policy, sign this proposal with Admin A, B **and C**, then
add the separate payer signature and submit it. Two admin signatures cannot be
substituted by a third payer signature. Read back the proposal hash, nonce, epoch,
ETA and execution deadline. Wait the required delay, then prepare a **new**
`recover_validators` transaction without `--propose`, using the exact same
validator arguments. Sign again with all three administrators and payer; submit
and verify the exact new validator set and consumed proposal.

For unpause, follow the same propose/wait/prepare-execution sequence with the
ordinary threshold. A recent pause adds its own minimum delay. Recovery
proposals require recovery authority for cancellation and cannot be replaced by
validator veto messages. An expired, cancelled, consumed or old-epoch proposal
is not executable. Admin pause has no proposal delay or embedded message expiry.

## Different Computers And Custody

Exchange only public packages and independently verified manifests/ABIs over
an accepted channel. Each administrator keeps their own encrypted wallet and
password locally. Inspect the received package, confirm the same ID, sign to a
new output file and return that file. Do not exchange keys or passwords.

Several wallets on one computer, controlled by one person, are a **centralized
rehearsal**. Distinct addresses and a 2-of-3/3-of-3 policy do not provide
independent administration, separate devices, separate recovery custody or
protection against one compromised account controlling the quorum.

## Verification And Remaining Qualification

```bash
npm test
npm run build
node tests/vortex-local-e2e.js /path/to/exact-clean-pinned-v2-checkout
```

The last command is explicit opt-in. It currently requires the dedicated
`colima-vortex-v2-audit` context, digest-pinned Koinos images, the reviewed
fresh-initializer 48-hour artifact and cached local-chain dependencies in the
read-only `vortex-fresh-work-20261003` volume. It creates new chain/exercise
volumes and a fresh official ABI metadata service (v1.1.0 image digest
`3733ece76ce2f618afeecc5f2b9b6f5022cc9d0ebf43064bed0c6698e819b70a`).
It uses a fresh explicit `10.254.x.0/24` internal-only Docker network (collisions
fail closed, and retained networks are not deleted) and a bounded native loopback relay,
synthetic hidden-input wallets and native
installed `kcli`, and stops only its new containers. It never resumes an old
chain or uses a public network. Bootstrap is a test harness, not a generic
administration command. Local block-time advancement is not 48 hours of real
operator monitoring. The chain starts in the past and advances full delays,
without disabling the real node's future-timestamp guard. The controlled miner
holds a stable head during preflight, then mines submitted transactions through
LIB finality. This is not an independently operated PoB producer or a busy-chain
availability test. Failed attempts are retained as diagnostics.

Raw Wasm verification uses `chain.invoke_system_call` and requires a node
`--system-call-buffer-size` large enough for the reviewed artifact. The lab uses
`700000`; CLI response/code sizes remain bounded. A smaller node buffer refuses
the check rather than silently trusting only a declared hash. Membership reads
use read-only contract-scoped caller context; no storage is written by preflight.

See [implementation status](VORTEX_IMPLEMENTATION_STATUS.md) for the measured
result, not a presumed success. Production still requires independent review,
reproducible final artifact/source mapping, authenticated policy distribution,
real custody/restore/device acceptance, independent RPC/finality evidence,
actual public-node capability/deployment qualification and explicit human approval. Unsupported setup,
token administration, code upgrades and validator-message signing remain refused.
