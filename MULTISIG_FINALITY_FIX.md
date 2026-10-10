# PR #2 Finality Correction

Date: 10 October 2026. Base: `00813ff8ba6806836acdd9f231a9cd3de0736f20`, then the open
[PR #2](https://github.com/pgarciagon/kcli/pull/2) head when work started. The base branch is
`29d182d4843c49b09bb99040a2638e44054f84ad`. The initial correction was prepared on
`codex/multisig-finality-fix` in a separate checkout. That correction candidate kept package version 1.6.0;
the separately prepared software release is kcli 1.7.0, with contract template 1.0.0 unchanged.

## Correction

`findIncluded()` previously passed the included transaction height as `corroborate()`'s minimum
irreversible height before deciding whether inclusion was reversible. With canonical block 100 and
both RPC LIBs at 90, this rejected normal pending finality. Submission treated that exception as failed
readback and ended `--wait` immediately. Bootstrap submission and verification used the same helper.

The initial production correction removes that premature minimum argument. Preliminary corroboration still
requires fresh compatible heads, matching canonical IDs and agreement at the common positive LIB.
Independent exact transaction bodies, valid signatures, receipts and events remain required. A terminal
result still requires BOTH LIBs at or above the transaction height. Existing final canonical rechecks,
read deadlines, submission journals, nonce locks and no-automatic-resend protections remain unchanged.
No new exception suppression or retry of submission is introduced.

A fresh independent agent review then identified three additional client issues. Inclusion now binds
the enclosing block ID/header height and receipt ID/height to the canonical block item on both RPCs.
After normal common-chain corroboration, a witness head below the transaction height returns explicit
`unknown` evidence and keeps the existing wait loop running. It does not weaken fork, freshness, skew,
signature, receipt or event checks. The multisig journal now fsyncs each parent entry and directory before
broadcast, including existing directories left by an interrupted first-use attempt. Sync failures stop
before any send. These changes are confined to multisig; shared Vortex and secure-file helpers are unchanged.

## Status And Exit Codes

| Command | Status | Exit | Meaning |
| --- | --- | --- | --- |
| submit / reconcile | included | 3 | Canonical inclusion, not yet irreversible on both Mainnet RPCs. |
| submit / reconcile | included-reverted | 3 | Reverted receipt in a reversible block; not a final failure. |
| submit / reconcile | irreversible-and-verified | 0 | Both LIBs cover inclusion, with verified payment event or policy readback. |
| submit / reconcile | reverted | 1 | Canonical reversion is irreversible on both RPCs. |
| submit | submitted-unconfirmed | 3 | Inclusion/readback unavailable or untrusted; investigate by read-only reconciliation. |
| reconcile | unknown | 3 | No canonical inclusion proved, or final policy readback does not match. |
| submit-deploy | included / included-reverted | 3 | Bootstrap is pending; no manifest is produced. |
| submit-deploy | irreversible / reverted | 0 / 1 | Both RPCs report terminal bootstrap success / reversion. Verification is still required before funding. |
| verify-deployment | included-not-irreversible / included-reverted / unknown | 3 | Bootstrap finality not established; no manifest. |
| verify-deployment | observation-not-irreversible | 3 | Bootstrap is final, checklist observation anchors are not; no manifest. |
| verify-deployment | deployment-verified | 0 | Bootstrap and all observation anchors finalized on both RPCs; only then can the CLI write a manifest. |
| verify-deployment | reverted / refused | 1 | Final bootstrap reversion or unsafe deployment checks; no manifest. |
| read-only commands | verification exception | 1 | Genuine RPC failure, inconsistent evidence or invalid input; not ordinary pending finality. |

`submit` and `submit-deploy` continue polling normal reversible inclusion until their existing wait
ends or finality is established. The wait is a polling budget, not an exact wall-clock stop: an in-flight
read and the existing one-second polling sleep can extend it, bounded by the provider command deadline.
`verify-deployment --wait` retains its existing observation-finality meaning: it does not first wait for
a reversible bootstrap. Run it again later when bootstrap finality is pending. Observation polling is
every three seconds, also bounded by the provider deadline.

A corroborated witness whose head has not reached the candidate transaction block is ordinary pending
evidence, not an exception. Reconciliation returns `unknown` with an explanation; submission keeps
waiting and returns `submitted-unconfirmed` at its deadline if corroboration never becomes available.

Never rebuild, re-sign or automatically resend because any pending/unknown result occurred. The same
intent and nonce lock persist after waiting, timeout, success or failure. Protection is machine-local;
it does not coordinate independent submission operators.

## Regression And Validation

Tests were added before changing production source. The initial new 16-test run had 15 failures and
one pass. A configured five-second transfer wait returned `submitted-unconfirmed` after approximately
54 ms; the policy wait returned after approximately 43 ms. Read-only reconciliation and bootstrap
verification raised `Independent irreversible finality is not established.` Normal inclusion, witness
lag and reversible reversion could not reach their expected pending statuses.

After the source correction, two test assertions were refined without changing production code: the
policy retry models a reorganized-away pending policy to reach the journal guard instead of the earlier
policy-mismatch guard, and invalid-signature testing uses decodable compact bytes rather than malformed
base64. The resulting 16 tests passed. Five-second transfer and policy waits reached
`irreversible-and-verified` after approximately 1081 ms and 1070 ms respectively, each with exactly one
submission. Additional built-CLI policy cases extend the final regression suite to 18 tests.

The complete PR suite passes all 139 tests (121 existing plus 18 new), with zero failures, under locked
koilib 9.2.0 on Node 23.11.0. The full run took approximately 30 seconds and rebuilt TypeScript first.
In that run the five-second transfer and policy waits finished after 1093 ms and 1054 ms, respectively,
both verified with exactly one send. CLI payment/policy and bootstrap cases also passed. A second complete
build/suite run on Node 22.12.0 also passed 139/139 tests in approximately 29 seconds. Node 22 emitted the
existing dependency's `punycode` deprecation warning; it did not affect the result.
`git diff --check` passes. Hash comparisons verified the primary checkout's 108 tracked/untracked/build
files, Git HEAD/branch/index and both installed-link targets unchanged. The Homebrew executable reports
1.6.0 when checked with a disposable HOME; the isolated built CLI exposes the multisig command group.

The synthetic suite covers payment and policy submission/reconciliation, reversible canonical inclusion,
either RPC lagging finality, finality advancement while waiting, reversible then irreversible reversion,
deadline expiry, forks, conflicting receipts/events, body/signature tampering, genuine RPC failures and
final canonical rechecks. Bootstrap tests cover submit-deploy, pending/reverted results, observation
finality and verify-deployment. Child-process CLI tests use this checkout's built executable through an
isolated PATH and disposable HOME, real review attestations made with disposable Ed25519 keys, and
test-only HTTPS-name routing exclusively to loopback JSON-RPC simulators. They verify exits 0/1/3 and
prove no deployment or policy manifest is written for nonfinal results.

Journal assertions verify the exact signed package and transaction JSON bytes, private intent/nonce
files before the send, persistent protection during readback and after waiting, one primary submission,
zero witness submissions, and refusal of same-ID or competing-nonce resubmission after timeout.

The review follow-up added six regressions before editing production source: all six failed. Enclosing
anchor mismatches were accepted, witness lag ended payment/policy/bootstrap waits after 28-49 ms, and
the first-use parent fsync failure did not stop submission. All six pass after the corrections. A
subsequent test-only review observation was resolved by computing the expected journal path without
calling the syncing helper inside the broadcast assertion. The complete suite then passed 145/145
tests on Node 22.12.0 (36.4 s) and Node 23.11.0 (37.1 s); the final assertion also passed in isolation.
Directory fsync ordering is instrumented, not a power-loss experiment or a guarantee about storage hardware.

Reproduction commands (set `bin` to a directory whose `kcli` links to THIS checkout's `dist/index.js`,
and `home` to a newly created private disposable directory):

```bash
env HOME="$home" PATH="$bin:$PATH" npm test
env HOME="$home" PATH="$bin:$PATH" node --test tests/multisig-finality.test.js
```

## Limits

Synthetic client/CLI validation is not Mainnet qualification, independently operated RPC evidence,
a contract audit, or proof of foundation custody. Follow-up release validation uses new disposable
local chains and separate arm64/amd64 builds, not public-chain transactions or real wallets. See
[release validation](MULTISIG_RELEASE_VALIDATION.md) for the fresh results and limitations. Contract/ABI,
shared Vortex helper, transport design, unrelated commands and version metadata remain unchanged in
this correction. The primary checkout and its installed kcli are outside this work.

The human approved final tested/reviewed SHA bc6c1b1aff90080b6416dee9701ecd5e80df1553. GitHub merged
PR #2 as 35679b75dab724d7c227bab12355d9eb87777445. Release 1.7.0 follows in an isolated checkout,
with its own exact-commit tests, package validation and checksummed asset verification. No npm registry
publication or production activation is authorized.
