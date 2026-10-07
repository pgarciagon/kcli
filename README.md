# kcli - Koinos CLI

Current version: `1.5.0`

A command line tool for interacting with the Koinos blockchain, built with TypeScript and koilib.

## Installation

```bash
npm install
npm run build
npm link
```

## Development

Run in development mode:

```bash
npm run dev -- <command>
# or after linking:
kcli <command>
```

Run the focused wallet/Vortex tests:

```bash
npm test
```

Vortex V2 local administration is available from source, not a tagged release. Named
encrypted wallets and detached-signing commands are described in the
[CLI administrator guide](VORTEX_ADMINISTRATOR_GUIDE.md); the
[implementation status](VORTEX_IMPLEMENTATION_STATUS.md) distinguishes tests
from actual contract execution. These workflows do not use Kondor or a custom
administration website and do not modify the existing default wallet/config.
The opt-in fresh-chain exercise is documented separately; `npm test` does not
start Docker or operate a public chain. Public-chain Vortex use is disabled.

## Build

```bash
npm run build
```

## Usage

### Global Options

- `-n, --network <network>` - Network to use (`mainnet` or `testnet`)
- `-r, --rpc <url>` - RPC endpoint URL override
- `-c, --changes` - Show latest changes and exit

### Commands

#### Get Chain Info
```bash
kcli chain-info
kcli --network testnet chain-info
```

#### Get Block Content
```bash
kcli block <height>           # By block height
kcli block 1000000
kcli block <blockId>          # By block ID
kcli block --full 1000000     # Show full transaction details
```

#### Check KOIN/VHP/Mana Balance
```bash
kcli balance <address>
kcli balance 1NsQbH5AhQXgtSNg1ejpFqTi2hmCWz1eQS
```

#### Check VHP Balance
```bash
kcli vhp <address>
```

#### Check Any Token Balance (KCS-4)
```bash
kcli token-balance <contractId> <address>
```

#### Transfer KOIN
```bash
kcli transfer <to> <amount>
kcli transfer <to> <amount> --dry-run
kcli transfer <to> <amount> --password-file ~/.kcli/wallet-password.txt --yes
kcli --network testnet transfer <to> 10
```

Transfers KOIN from the encrypted wallet imported with `kcli import-wallet`. The command shows transaction details before signing and requires typing `TRANSFER` to confirm.
Use `--password-file <path>` with a local `0600` file for non-interactive automation, and `--yes` only when you intentionally want to skip the confirmation prompt.

#### Transfer Any Token (KCS-4)
```bash
kcli token-transfer <contractId> <to> <amount>
kcli token-transfer <contractId> <to> <amount> --dry-run
kcli token-transfer <contractId> <to> <amount> --password-file ~/.kcli/wallet-password.txt --yes
```

Transfers any KCS-4 token from the encrypted wallet. The token contract is queried for symbol and decimals before building the transaction.

#### Official Testnet Info
```bash
kcli testnet-info
kcli faucet-info
```

Official Koinos Foundation testnet details:

- JSON-RPC: `https://testnet.koinosfoundation.org/jsonrpc`
- Health: `https://testnet.koinosfoundation.org/health`
- Chain ID: `EiAIKVvm6-V2qmsmUvPJy09vCCLbtn9lHFpwrJbcTIEWRQ==`
- KOIN contract: `1FaSvLjQJsCJKq5ybmGsMMQs8RQYyVv8ju`
- VHP contract: `17n12ktwN79sR6ia9DDgCfmw77EgpbTyBi`
- PoB contract: `1MAbK5pYkhp9yHnfhYamC3tfSLmVRTDjd9`
- Faucet: `https://t.me/KoinosTestnetFaucetBot`

To request testnet vKOIN, open the Telegram faucet and send:

```txt
/faucet YOUR_KOINOS_ADDRESS
```

The testnet can reset. Do not use it for production funds or durable production state.

#### Generate New Wallet
```bash
kcli generate-wallet
```

#### Derive Kondor-Compatible Accounts from Seed
```bash
kcli derive-from-seed "<seed phrase>" -n 5
```

#### Get Address from Private Key
```bash
kcli address <privateKeyWIF>
```

#### Get Account Nonce
```bash
kcli nonce <address>
```

#### Get Resource Credits (Mana)
```bash
kcli rc <address>
```

#### Read Contract Method
```bash
kcli read-contract <contractId> <method> --args '{"key": "value"}'
kcli read-contract 15DJN4a8SgrbGhhGksSBASiSYjGnMU8dGL name
```

#### Import Encrypted Wallet
```bash
kcli import-wallet <privateKeyWIF>
```

#### Show Current Wallet
```bash
kcli wallet
```

#### Delete Stored Wallet
```bash
kcli delete-wallet
```

#### Register Producer Public Key (PoB)
```bash
kcli register-producer-key <producerAddress> <publicKey>
kcli register-producer-key <publicKey>  # Uses configured main producer address
kcli register-producer-key 14MHW6TF8gw8EuMRLCJc2PQHLzZLKuwGqb Aq4Ps_Ch-f8OZDnpQOov2SiMvdYyA5tn0oWa36QWnTeH
kcli register-producer-key <producerAddress> <publicKey> --dry-run
kcli register-producer-key <producerAddress> <publicKey> --password-file ~/.kcli/wallet-password.txt --yes
```

This command sends a transaction to the Proof-of-Burn contract (`159myq5YUhhoVWu3wsHKHiJYKPKGUrGiyv`) and calls `register_public_key`.

- `producerAddress`: address that will produce blocks
- `publicKey`: block producer public key in base64url format (typically from `$KOINOS_BASEDIR/block_producer/public.key`)
- `--dry-run`: prepare and display the transaction without sending it
- `--password-file <path>`: read the wallet password from a local `0600` file
- `--yes`: skip the confirmation prompt

If the producer address is omitted, `kcli` uses `mainProducerAddress` from `~/.kcli/config.json`.

#### Get Registered Producer Public Key (PoB)
```bash
kcli get-producer-key <producerAddress>
kcli get-producer-key              # Uses configured main producer address
```

This command reads PoB `get_public_key` and returns the public key assigned to the producer address (if any).

#### Producer Dashboard (Interactive)
```bash
kcli producer-dashboard
kcli producer-dashboard --window 240 --interval 3 --top 25
kcli producer-dashboard --view peers
kcli producer-dashboard --balance-interval 30 --pool-interval 600 --rpc-concurrency 2 --rpc-stats
```

Shows a live text-based dashboard with two views: `producers` and `peers`.

- `--window`: number of recent blocks to analyze (default: `120`)
- `--interval`: screen and producer-activity refresh interval in seconds (default: `5`); it does not refetch every balance
- `--top`: number of producers to display (default: `20`)
- `--view`: initial view (`producers` or `peers`, default: `producers`)
- `--balance-interval`: balance and total-supply polling interval, `1-3600` seconds (default: `30`)
- `--pool-interval`: pool polling interval, `1-86400` seconds (default: `600`)
- `--rpc-concurrency`: dashboard-only request and HTTP socket limit, `1-4` (default: `2`)
- `--rpc-timeout`: absolute timeout per RPC attempt, `1-60` seconds (default: `10`)
- `--rpc-retries`: additional attempts for recoverable reads, `0-3` (default: `2`, exponential backoff with jitter)
- `--rpc-stats`: cumulative request attempts, errors, retries, concurrency and socket counters
- Switch views while running with `1` (producers) and `2` (peers)
- Exit with `q` or `Ctrl+C`
- Includes per-producer `KOIN` and `VHP` columns (shown as whole numbers, no decimals)
- Shows estimated APY only when every active producer's VHP and both token supplies are available; stale inputs produce a labeled stale estimate
- Shows total virtual supply (`VHP + KOIN`)
- Detects Fogata pools by calling `get_pool_params`; highlights those producer addresses in orange and shows pool `name`
- Peers view shows active peer endpoint (IP:port), geolocation, ping in seconds, seen ratio, and a role heuristic (`Seed`, `Likely Producer`, `Possible Producer`, `Relay/Unknown`)
- Seed detection uses local node `p2p.peer` config entries when available (`$KOINOS_BASEDIR/config/config.yml`, `~/.koinos/config/config.yml`, `~/.koinos/config.yml`, `/etc/koinos/config.yml`)
- Geolocation is best-effort using `ipwho.is`; role classification is heuristic (not an on-chain proof)
- Block window fetch is automatically paginated, so `--window` can be greater than `1000`

Reads are staggered and cached in memory by network, endpoint, contract, method
and arguments. KOIN and VHP update independently. Temporary failures retain the
last successful value with `stale:<age>`; `n/a` means no valid value is available,
never zero. Pool errors mean unknown, not proof that an address is not a pool.
The screen keeps updating during slow reads, without overlapping activity scans
or accumulating polling rounds. The dashboard's own HTTP/HTTPS agent reuses at
most the configured number of sockets and closes idle sockets after one second.
Other commands and their transports are unchanged.

Thirty seconds trades block-by-block balance accuracy for substantially fewer
reads; the screen shows the oldest available balance age. Pool names normally
change much less frequently, so their default remains ten minutes. These are
polling targets, not freshness guarantees: startup, many producers, slow RPCs or
retries can delay results. Cached balances and APY are not head-anchored and must
not be used as transaction preflight. See [dashboard reliability and measured
validation](DASHBOARD_RPC_RELIABILITY.md) for limitations and reproducible checks.

#### Burn KOIN to Receive VHP
```bash
kcli burn -p 95        # Burn 95% of KOIN balance
kcli burn -a 10        # Burn exactly 10 KOIN
kcli burn -p 95 --dry-run
kcli burn -a 10 --password-file ~/.kcli/wallet-password.txt --yes
```

#### Config
```bash
kcli config --show
kcli config --network testnet
kcli config --rpc https://testnet.koinosfoundation.org/jsonrpc
kcli config --default-account <address>
kcli config --main-producer-address <address>
```

Default main producer address:

```txt
14MHW6TF8gw8EuMRLCJc2PQHLzZLKuwGqb
```

### Using Custom RPC

```bash
kcli --rpc http://localhost:8080 chain-info
kcli --network testnet --rpc http://localhost:8080 chain-info
```

### Using the Official Testnet

Use the testnet for one command:

```bash
kcli --network testnet chain-info
kcli --network testnet balance <address>
kcli --network testnet token-balance 1FaSvLjQJsCJKq5ybmGsMMQs8RQYyVv8ju <address>
```

Or make it the default:

```bash
kcli config --network testnet
kcli chain-info
```

`balance`, `vhp`, `burn`, producer key, and producer dashboard commands use the official testnet KOIN, VHP, and PoB contract IDs when `--network testnet` is selected.

### Show Latest Changes

```bash
kcli --changes
```
