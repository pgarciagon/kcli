# Producer Dashboard RPC Reliability

Implemented locally on 7 October 2026, at the existing unreleased version 1.6.0.
The measurements below describe that combined development checkout, not a
release of its unrelated features. Dashboard source publication retains the
current public package version 1.5.0 and excludes older unpublished KFS,
transfer and restricted-mainnet Vortex changes. No tag or registry release is
part of this source publication.
This change is scoped to `producer-dashboard`. It does not change another
command's provider, signing, configuration or transaction behavior.

## Scheduling And Freshness

- Screen and producer activity: five seconds by default. Rendering does not
  await network reads. Only one head/block-window scan can run at a time;
  missed scan ticks are skipped, not queued. Existing paginated block scanning
  is retained without incremental indexing or fork-cache changes.
- Balances and token supplies: thirty seconds after each successful read.
  Compared with five-second polling, this targets roughly one sixth of the
  steady-state balance traffic. Balances can change every block; this is an
  explicit load/freshness compromise, not an execution-state snapshot.
- Pool metadata: ten minutes, retaining the previous intended interval because
  names and configuration usually change less often than balances. A failure
  is unknown rather than a cached negative pool classification.
- Data reads start at least 150 ms apart (a 100 ms scheduler tick can make this
  longer). Successful completions preserve the stagger across subsequent TTLs.
  Only the currently wanted producer/supply/pool entries are polled.
- Cache identity includes selected network/expected chain, canonical endpoint,
  contract, method and stable structured arguments. Up to 4,096 entries are
  retained; inactive history is evicted before new work is admitted. If active
  demand exceeds capacity, missing entries remain unknown with a warning.

Each item retains its last successful value and timestamp independently.
Expired or failed values include `stale:<age>`. Unknown values are `n/a`.
The oldest available visible balance age is also displayed. A successful empty
protobuf uint64 result is the protocol's zero, but absent/malformed RPC results
are errors and never turn into zero. Missing active VHP or either total supply
prevents APY calculation. Complete stale inputs produce a labeled stale APY;
its age is the oldest input age. A missing producer KOIN balance does not affect
that VHP-based formula if the necessary supplies and VHP are available.

## Transport And Failure Bounds

`DashboardProvider` subclasses koilib `Provider` and overrides `call`; inherited
head/contract reads therefore use the dashboard transport, not koilib's
`cross-fetch` implementation. No global agent or dependency is patched. The
provider accepts only the four read methods used by this command; writes fail
before network access. The selected chain ID is checked before contract polling.

The dedicated Node HTTP or HTTPS agent uses `keepAlive`, `maxSockets`,
`maxTotalSockets` and `maxFreeSockets`, all bounded by the configured concurrency
(default two). Actual reuse cancels the idle timer; free sockets are destroyed
after one idle second and all owned requests/sockets are destroyed on exit.
An application queue defaults to eight pending jobs; duplicate in-flight calls
share one promise. Background data scheduling holds at most two jobs by default,
so repeated screen ticks do not append full producer rounds to the queue.

Each attempt has an absolute ten-second timeout including connection and body
transfer. Recoverable session overload, HTTP 408/429/500/502/503/504 and selected
connection errors receive at most two additional attempts. Delays start at
250 ms, double and add up to 20% jitter; a job keeps its concurrency slot during
backoff. Permanent contract/data errors are not retried immediately. A failed
cache item has its own cooldown: transient failures start at five seconds and
back off up to the smaller of its polling interval or sixty seconds; permanent
failures wait its polling interval. Responses are bounded to 32 MiB, JSON/RPC
identity and contract-result presence are checked, and redirects are not followed.
Only three grouped warning reasons are rendered; raw server messages are not
printed. Pool names are stripped of terminal controls.

Options: `--balance-interval`, `--pool-interval`, `--rpc-concurrency`,
`--rpc-timeout`, `--rpc-retries`, and optional `--rpc-stats`. The two-connection
default leaves potential room on a four-session server, but cannot reserve
slots against other clients. Multiple dashboards each have their own cap.

## Validation

The simulated RPC counts actual accepted TCP sessions, all open sockets and
active requests. Idle keep-alive sessions count against its four-session limit.
Transient overload, timeouts, permanent errors and missing results are exercised
through actual koilib contract serialization and the installed CLI.

An isolated transport test completed sixteen reads using two actual connections,
at most two simultaneous requests, no errors, and zero open sockets after the
idle timeout. Raw koilib's twelve concurrent reads reproduced session overload.

A retained pre-change compiled CLI and the installed new CLI were each observed
for 27 seconds, with a five-second interval, twelve-block window and four visible
producers. Both issued six head and six block-window calls:

| Metric | Before | After |
| --- | ---: | ---: |
| Contract reads | 64 | 14 |
| All RPC calls | 76 | 27 |
| Session-limit errors | 26 | 0 |
| Peak open TCP sockets at server | 8 | 1 |
| Total TCP connections | 33 | 6 |

Contract reads fell 78.13%; total calls fell 64.47%, including the new one-time
chain check. The simulator's fast responses and staggering only needed one
socket during that CLI run; a separate slow-response test proves the two-socket
upper bound under concurrent load. Six screens were drawn by each CLI; the new
first screen intentionally shows pending activity rather than blocking startup.
The cache comparison uses a controlled clock to test thirty-second expiry; the
CLI comparison above uses real wall-clock time. Neither is a node load benchmark.

Both installed links resolve to this checkout's rebuilt `dist/index.js` and
report 1.6.0; installed help exposes the dashboard tuning options. The full
checkout passes 94 tests, including 25 new dashboard cases. These cover both
directions of balance independence, stale values/ages and recovery in actual
CLI output, missing-VHP/supply APY refusal, stale APY, retained activity, in-flight
deduplication, scoped cache keys, bounded history/queues, staggering, idle socket
release, read-only refusal, and unchanged non-dashboard koilib behavior.

### Source Publication Check

Before the authorized source commit/push, an isolated export of the exact staged
code compiled and passed all 53 tests: 25 dashboard cases and the 28 previously
published wallet/local-Vortex cases. CLI integration tests used that export's
executable through a temporary PATH, not the combined development binary.
Dashboard option parsing and mainnet read-only chain checks are self-contained;
they do not depend on unpublished KFS or transaction-network changes.

The staged package, lockfile, README and exported executable retain version
1.5.0. The installed combined development checkout remains 1.6.0. Older local
KFS, transfer and restricted-mainnet Vortex changes were preserved but excluded
from this dashboard commit. No tag or package-registry release was made.

### Limited Live Observation

The owner's existing loopback-forwarded private API returned the expected
mainnet chain ID. Two strict three-second comparator preflights timed out;
their provider resources were released, and no service or connection owned by
another client was operated. A direct twelve-second installed-CLI observation
then produced three screens, two with activity. Its last rendered counters
reported twelve attempts, zero errors/retries and maxima of two requests and
two sockets. This is a short snapshot, not sustained availability evidence.

Repeating the protected comparator with the normal ten-second attempt budget
completed both 27-second observations:

| Live metric | Before | After |
| --- | ---: | ---: |
| All forwarded RPC calls | 21 | 31 |
| Contract reads | 17 | 21 |
| Head / block-window reads | 2 / 2 | 5 / 4 |
| Relay backend read failures | 4 | 4 |
| Maximum relay backend sockets | 2 | 2 |

These are not matched successful rounds: slow/failed reads limited the old
blocking renderer, while the new renderer kept drawing six screens and exposed
pending/stale state. The old observation recorded no screen containing its
`Updated:` timestamp; failure screens were not counted by that initial counter.
The comparator now counts failure screens as well and withholds percentage
reductions when activity-round counts differ. No live call-reduction percentage
or root cause for the four generic read failures is claimed. The stable simulator
comparison above is the measured reduction evidence; a longer live comparison
under equivalent successful workload remains pending.

Sanitized observations are saved in
[`evidence/2026-10-07-dashboard-rpc-validation.json`](evidence/2026-10-07-dashboard-rpc-validation.json).

```bash
npm test
# Keep a separate pre-change compiled CLI artifact before rebuilding.
node tests/dashboard-measure.cjs dist/dashboard-before.cjs
# Optional live reads: explicit loopback endpoint, never server changes.
KCLI_DASHBOARD_LIVE_READS=1 node tests/dashboard-measure.cjs dist/dashboard-before.cjs http://127.0.0.1:PORT/
```

The optional live comparator relays both versions through at most two backend
sockets, protecting the limited API even during the old client's burst. It
measures client call counts and backend errors, not the old client's unrestricted
production socket behavior. It refuses non-loopback/authenticated URLs and checks
mainnet before forwarding any contract calls.

## Remaining Limits

- No atomic/head-anchored balance snapshot, APY accuracy guarantee or chain
  execution simulation is claimed. Balance and pool TTLs may need tuning for a
  particular workload; startup and high producer counts can leave pending data.
- This does not solve saturation caused by other clients, inadequate server
  capacity, a stalled SSH forward, or arbitrary network outages. No Teleno limit,
  service or access policy was changed.
- Head/block reads still fetch the requested window on every successful activity
  cycle; large windows can dominate load even when metadata is cached.
- Socket/concurrency integration tests use loopback HTTP. HTTPS uses the same
  bounded native-agent policy with default certificate verification but was not
  qualified against a constrained live HTTPS server.
- The peers view retains its separate geolocation/TCP-ping behavior; those
  connections are not sessions on the dashboard RPC endpoint.
- No real wallet was read/unlocked or real signature/transaction created during
  dashboard work. The recorded measurements preceded the subsequent authorized
  source commit/push; their evidence retains that historical scope. Existing
  unrelated local changes and the saved real configuration are preserved.

Primary transport references: [Node 22.12 HTTP agent API](https://github.com/nodejs/node/blob/v22.12.0/doc/api/http.md#class-httpagent)
and [koilib Provider source](https://github.com/joticajulian/koilib/blob/main/src/Provider.ts).
Installed koilib's `node_modules/koilib/lib/Provider.js` was inspected directly;
its `call` uses `cross-fetch` without a per-provider socket-agent option.
