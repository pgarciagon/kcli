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

#### Check KOIN Balance
```bash
kcli balance <address>
kcli balance 1NsQbH5AhQXgtSNg1ejpFqTi2hmCWz1eQS
```

#### Generate New Wallet
```bash
kcli generate-wallet
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

### Using Custom RPC

```bash
kcli --rpc http://localhost:8080 chain-info
```
