# Producer dashboard balance diagnosis — 7 October 2026

Scope: read-only diagnosis of missing producer KOIN/VHP balances through the owner’s local SSH-forwarded Teleno mainnet API. No source, server, signing or network-policy changes were made.

The dashboard launches producer work concurrently with Promise.all, and two parallel balance_of requests per producer. A failure of either request sets both displayed balances to n/a. The underlying error is retained internally but the rendered warning is generic.

A direct live RPC request reproduced HTTP 503 with JSON-RPC code -32001 and message “JSON-RPC session limit reached”. A subsequent head read timed out after 15 seconds. A running installed producer-dashboard process was observed on the Mac. The effective server YAML contains no JSON-RPC jobs override, and the inspected Teleno source defaults jsonrpc_jobs to 4, limits active HTTP sessions to that count, and returns that exact overload error. Read-only remote inspection observed four established connections on the loopback RPC port. Keep-alive connections can occupy session slots beyond individual request execution.

The screenshot’s two successful producer rows are consistent with two balance requests each using four session slots; exact per-request scheduling was not traced. An initial manually transcribed producer address failed local checksum validation and was discarded, not treated as evidence of an RPC fault. Fetching a fresh producer window was itself refused by the session limit before balance comparison could run.

Recommended correction: bound HTTP connections and request concurrency in the dashboard, account for pool/supply reads, and use bounded retry/backoff for temporary overload. Show sanitized concrete error reasons and retain independent KOIN/VHP outcomes. Raising production-node limits is a separate capacity/configuration decision. n/a means unavailable, never zero.
