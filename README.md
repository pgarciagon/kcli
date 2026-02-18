# kcli - Koinos CLI

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

## Build

```bash
npm run build
```

## Usage

### Global Options

- `-r, --rpc <url>` - RPC endpoint URL (default: https://api.koinos.io)
- `-c, --changes` - Show latest changes and exit

### Commands

#### Get Chain Info
```bash
kcli chain-info
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
```

This command sends a transaction to the Proof-of-Burn contract (`159myq5YUhhoVWu3wsHKHiJYKPKGUrGiyv`) and calls `register_public_key`.

- `producerAddress`: address that will produce blocks
- `publicKey`: block producer public key in base64url format (typically from `$KOINOS_BASEDIR/block_producer/public.key`)
- `--dry-run`: prepare and display the transaction without sending it

If the producer address is omitted, `kcli` uses `mainProducerAddress` from `~/.kcli/config.json`.

#### Burn KOIN to Receive VHP
```bash
kcli burn -p 95        # Burn 95% of KOIN balance
kcli burn -a 10        # Burn exactly 10 KOIN
kcli burn -p 95 --dry-run
```

#### Config
```bash
kcli config --show
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
```

### Show Latest Changes

```bash
kcli --changes
```
