# Fund RPC Compatibility

Software version: kcli 1.7.1. These changes are limited to Koinos Fund System
(KFS) reads and response decoding. They do not change the fund contract,
allocation rules, wallet format, multisig/Vortex workflows or burn behavior.

## ABI Metadata And The Read-Only Fallback

koilib fetches ABI metadata from `contract_meta_store.get_contract_meta`, an
optional RPC index. An empty index entry is not evidence that the deployed
contract or its ABI is absent from chain state.

Compatible RPC metadata remains preferred. Only when metadata is absent may
`fund-info`, `proposals`, `proposal` and `votes` use the bundled four-method
read interface. This requires the selected and actual Mainnet chain ID and
the exact default KFS address, `1A5BmMqV5jN5zBrdkhQumAfDZBzXLPBeN9`.
Testnet, custom contracts, malformed/incompatible metadata and transport errors
never activate the fallback. No alternate RPC is contacted automatically.

The bundled interface has no `update_vote` method; attempting vote preparation
on a read-only client fails before any further reads. Both signed `vote` and
`vote --dry-run` still require compatible RPC metadata on the selected network.
This patch does not repair an RPC index or authorize a service restart.

JSON read output identifies `abi_source` as `rpc-metadata` or
`bundled-read-only`. A single fallback notice is written to stderr, leaving
stdout parseable. Read failures exit 1 rather than inventing empty lists.

## Empty Protobuf Results

A successful JSON-RPC outer result can contain `{}`, `{ "result": "" }` or
only valid string-array `logs`. The nested contract-result bytes have implicit
protobuf presence; omitted default bytes therefore decode as an empty message.
Empty vote/proposal lists are valid, not a reason to fail a new voter.

The fund-specific decoder requires an object payload containing only `result`
and/or `logs`. It rejects missing outer envelopes, null/non-object payloads,
unknown fields, malformed logs and invalid bytes. Standard and URL-safe base64,
with or without padding, are checked for canonical decoded bytes. Unknown or
malformed allocations cannot silently become zero. Existing nonempty votes,
including expired records, still participate in the 100% allocation check.

## Examples

Select a network-compatible RPC explicitly; these examples do not alter saved
configuration. Replace the public address and project ID as appropriate.

```bash
kcli --network mainnet --rpc https://api.koinos.io/ fund-info --json
kcli --network mainnet --rpc https://api.koinos.io/ proposals --status active --all --json
kcli --network mainnet --rpc https://api.koinos.io/ proposal 10 --json
kcli --network mainnet --rpc https://api.koinos.io/ votes <public-address> --json
kcli --network mainnet --rpc https://api.koinos.io/ vote --percent 100 10 \
  --address <public-address> --dry-run
```

The vote example only prepares an unsigned transaction. It neither unlocks a
wallet nor reads a password file, signs, submits or simulates contract execution.
Insufficient balance/Mana, incompatible ABI or existing allocations may refuse
it. Real voting requires the existing confirmation and wallet safeguards.
Fund vote inclusion/readback is not irreversible finality.

## Sources And Validation Boundary

The read-only interface is independently described from pinned upstream
[fund.proto](https://github.com/koinos/koinos-contracts-as/blob/4fc33bbe0520a77a89619da1e9e6efe98e7c423c/contracts/fund/assembly/proto/fund.proto)
and [dispatcher](https://github.com/koinos/koinos-contracts-as/blob/4fc33bbe0520a77a89619da1e9e6efe98e7c423c/contracts/fund/assembly/index.ts).
See [protobuf JSON presence](https://protobuf.dev/programming-guides/json/#presence-and-default-values)
and the [chain RPC schema](https://github.com/koinos/koinos-proto/blob/master/koinos/rpc/chain/chain_rpc.proto).
Wire compatibility does not prove deployed-bytecode equivalence.

Before integration, the new tests reproduced the missing-ABI refusal and
malformed-response acceptance in 1.7.0. Valid protobuf-empty vote preparation
already passed in that release; its regression is retained so the stricter
decoder does not reintroduce the temporary local decoder failure reported earlier.

The regression suite covers all read commands, pagination, provenance, fallback
scope, refusal before wallet unlock, preserved fixture files, omitted/default
bytes, malformed envelopes/logs/base64, nonempty allocations, and synthetic
signed vote/update/removal against simulated RPCs. Release validation must test
both locked-source koilib and fresh tarball dependency resolution through the
candidate executable on isolated PATH/HOME. Public-chain execution, official
testnet fund deployment and independent security audit remain unverified.

## Release Validation On 10 October 2026

The locked source (koilib 9.2.0) passes the complete 161-test suite, including
41 fund tests, with 0 failures/skips on Node 22.12.0 and Node 23.11.0. Each
accepted run first asserts the real PATH executable and its 1.7.1 version.
Initial runs that could fall back to an older global executable were excluded;
the built entry point was made executable and both complete runs repeated.

A fresh protobuf-parser comparison against the pinned upstream source verifies
all 30 read-interface fields, both enums and all four dispatcher entry points.
Dependency lock data is unchanged apart from the package's two version fields.
The existing source dependency audit has 10 low-severity affected packages,
with no moderate/high/critical findings; this is not a security audit.

A bounded read-only relay to api.koinos.io allowed only chain ID, ABI metadata,
contract reads, account Mana and nonce reads, through at most one upstream
socket. `fund-info`, `proposals`, `votes` and an unsigned `vote --dry-run`
completed with 21 calls, zero attempted writes and zero submissions. The RPC
supplied compatible metadata; missing-index behavior is simulator evidence,
not a claim that this public endpoint has an empty index. No real wallet or
password was read. Dry-run success is not executed-vote or finality evidence.

Distribution gates additionally require an exact committed-source build,
fresh tarball dependency tests, package-content review, published-download
checksum verification and version/feature checks on each requested installation.
