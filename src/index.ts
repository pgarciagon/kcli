#!/usr/bin/env node

import { Command } from 'commander';
import { Provider, Contract, Signer, utils, Abi, Transaction } from 'koilib';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as readlineSync from 'readline-sync';
import { ethers } from 'ethers';
import tokenAbi from './abis/token.json';
import pobAbi from './abis/pob.json';
import packageJson from '../package.json';

const program = new Command();
const CLI_VERSION = packageJson.version;

const LATEST_CHANGES = [
  'Added global --changes option to display the latest release notes.',
  'register-producer-key now supports one-argument mode using mainProducerAddress from config.',
  'Added config support for --main-producer-address with default producer address bootstrap.',
];

function showLatestChanges(): void {
  console.log(`\n📝 kcli v${CLI_VERSION} - Latest Changes`);
  console.log('─'.repeat(50));
  LATEST_CHANGES.forEach((change, index) => {
    console.log(` ${index + 1}. ${change}`);
  });
  console.log('─'.repeat(50));
}

// Default RPC endpoint (can be overridden with -r flag)
const DEFAULT_RPC = 'https://api.koinos.io';
const DEFAULT_MAIN_PRODUCER_ADDRESS = '14MHW6TF8gw8EuMRLCJc2PQHLzZLKuwGqb';

// Mainnet contract addresses
const KOIN_CONTRACT = '19GYjDBVXU7keLbYvMLazsGQn3GTWHjHkK';
const VHP_CONTRACT = '12Y5vW6gk8GceH53YfRkRre2Rrcsgw7Naq';
const POB_CONTRACT = '159myq5YUhhoVWu3wsHKHiJYKPKGUrGiyv';

// Wallet and config file paths
const WALLET_DIR = path.join(os.homedir(), '.kcli');
const WALLET_FILE = path.join(WALLET_DIR, 'wallet.json');
const CONFIG_FILE = path.join(WALLET_DIR, 'config.json');

// Config interface
interface Config {
  defaultAccount?: string;
  rpc?: string;
  mainProducerAddress?: string;
}

// Load config file
function loadConfig(): Config {
  const defaultConfig: Config = {
    mainProducerAddress: DEFAULT_MAIN_PRODUCER_ADDRESS,
  };

  try {
    if (fs.existsSync(CONFIG_FILE)) {
      const data = fs.readFileSync(CONFIG_FILE, 'utf8');
      const parsed = JSON.parse(data) as Config;
      const merged = { ...defaultConfig, ...parsed };

      // Backfill missing values into config file
      if (!parsed.mainProducerAddress) {
        saveConfig(merged);
      }

      return merged;
    }
  } catch (error) {
    // Config file doesn't exist or is invalid, return empty config
  }

  // Create config file with defaults on first run
  saveConfig(defaultConfig);
  return defaultConfig;
}

// Save config file
function saveConfig(config: Config): void {
  ensureWalletDir();
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), { mode: 0o600 });
}

// Encryption settings
const ENCRYPTION_ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;
const IV_LENGTH = 16;
const SALT_LENGTH = 32;
const PBKDF2_ITERATIONS = 100000;
const AUTH_TAG_LENGTH = 16;

// Derive encryption key from password
function deriveKey(password: string, salt: Buffer): Buffer {
  return crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256');
}

// Encrypt data with password
function encrypt(data: string, password: string): { encrypted: string; salt: string; iv: string; authTag: string } {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const iv = crypto.randomBytes(IV_LENGTH);
  const key = deriveKey(password, salt);
  
  const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, iv);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();
  
  return {
    encrypted,
    salt: salt.toString('hex'),
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
  };
}

// Decrypt data with password
function decrypt(encryptedData: { encrypted: string; salt: string; iv: string; authTag: string }, password: string): string {
  const salt = Buffer.from(encryptedData.salt, 'hex');
  const iv = Buffer.from(encryptedData.iv, 'hex');
  const authTag = Buffer.from(encryptedData.authTag, 'hex');
  const key = deriveKey(password, salt);
  
  const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);
  
  let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}

// Prompt for password (hidden input)
function promptPassword(prompt: string = 'Enter password: '): string {
  return readlineSync.question(prompt, { hideEchoBack: true });
}

// Prompt for password with confirmation
function promptNewPassword(): string {
  const password = readlineSync.question('Enter new password: ', { hideEchoBack: true });
  const confirm = readlineSync.question('Confirm password: ', { hideEchoBack: true });
  
  if (password !== confirm) {
    throw new Error('Passwords do not match');
  }
  
  if (password.length < 8) {
    throw new Error('Password must be at least 8 characters long');
  }
  
  return password;
}

// Wallet management functions
function ensureWalletDir(): void {
  if (!fs.existsSync(WALLET_DIR)) {
    fs.mkdirSync(WALLET_DIR, { recursive: true, mode: 0o700 });
  }
}

interface EncryptedWallet {
  address: string;
  encryptedKey: {
    encrypted: string;
    salt: string;
    iv: string;
    authTag: string;
  };
  createdAt: string;
}

function saveWallet(privateKeyWif: string, address: string, password: string): void {
  ensureWalletDir();
  const encryptedKey = encrypt(privateKeyWif, password);
  const walletData: EncryptedWallet = {
    address,
    encryptedKey,
    createdAt: new Date().toISOString(),
  };
  fs.writeFileSync(WALLET_FILE, JSON.stringify(walletData, null, 2), { mode: 0o600 });
}

function loadWalletFile(): EncryptedWallet | null {
  if (!fs.existsSync(WALLET_FILE)) {
    return null;
  }
  const data = fs.readFileSync(WALLET_FILE, 'utf-8');
  return JSON.parse(data);
}

function loadWallet(password: string): { address: string; privateKey: string } | null {
  const walletFile = loadWalletFile();
  if (!walletFile) {
    return null;
  }
  
  try {
    const privateKey = decrypt(walletFile.encryptedKey, password);
    return {
      address: walletFile.address,
      privateKey,
    };
  } catch (error) {
    throw new Error('Invalid password');
  }
}

function deleteWallet(): boolean {
  if (fs.existsSync(WALLET_FILE)) {
    fs.unlinkSync(WALLET_FILE);
    return true;
  }
  return false;
}

// Function to fix ABI from chain (converts read-only to read_only, entry-point to entry_point)
function fixAbi(abi: Abi): Abi {
  if (!abi || !abi.methods) return abi;
  
  Object.keys(abi.methods).forEach((name) => {
    const method = abi.methods[name] as any;
    
    // Convert entry-point to entry_point
    if (method['entry-point'] && !method.entry_point) {
      method.entry_point = parseInt(method['entry-point'], 16);
      delete method['entry-point'];
    }
    
    // Convert read-only to read_only
    if (typeof method['read-only'] !== 'undefined' && typeof method.read_only === 'undefined') {
      method.read_only = method['read-only'];
      delete method['read-only'];
    }
  });
  
  return abi;
}

// Helper function to create a system token contract (KOIN, VHP) with bundled ABI
function getSystemTokenContract(provider: Provider, contractId: string): Contract {
  return new Contract({
    id: contractId,
    abi: tokenAbi,
    provider,
  });
}

// Helper function to create a token contract with ABI fetched from chain
async function getTokenContract(provider: Provider, contractId: string): Promise<Contract> {
  const contract = new Contract({
    id: contractId,
    provider,
  });
  
  // Fetch ABI from chain
  await contract.fetchAbi({ updateFunctions: false, updateSerializer: true });
  
  // Fix the ABI format
  if (contract.abi) {
    contract.abi = fixAbi(contract.abi);
    contract.updateFunctionsFromAbi();
  }
  
  return contract;
}

program
  .name('kcli')
  .description('A Koinos blockchain command line tool')
  .version(CLI_VERSION)
  .option('-r, --rpc <url>', 'RPC endpoint URL', DEFAULT_RPC)
  .option('-c, --changes', 'Show latest changes and exit');

program.hook('preAction', () => {
  const opts = program.opts<{ changes?: boolean }>();
  if (opts.changes) {
    showLatestChanges();
    process.exit(0);
  }
});

program.action(() => {
  const opts = program.opts<{ changes?: boolean }>();
  if (opts.changes) {
    showLatestChanges();
    return;
  }
  program.help({ error: true });
});

// Get chain info
program
  .command('chain-info')
  .description('Get blockchain information')
  .action(async () => {
    const opts = program.opts();
    const provider = new Provider([opts.rpc]);
    
    try {
      const headInfo = await provider.getHeadInfo();
      console.log('\n📊 Chain Info:');
      console.log(`  Head Block: ${headInfo.head_topology?.height}`);
      console.log(`  Block ID: ${headInfo.head_topology?.id}`);
      console.log(`  Last Irreversible Block: ${headInfo.last_irreversible_block}`);
    } catch (error) {
      console.error('Error fetching chain info:', error);
    }
  });

// Get block content
program
  .command('block')
  .description('Get block content by height or ID')
  .argument('<heightOrId>', 'Block height (number) or block ID (base64/hex)')
  .option('--full', 'Show full transaction details')
  .action(async (heightOrId: string, options: { full?: boolean }) => {
    const opts = program.opts();
    const provider = new Provider([opts.rpc]);
    
    try {
      let blockId: string | undefined;
      let blockHeight: number | undefined;
      
      // Check if it's a number (height) or string (ID)
      if (/^\d+$/.test(heightOrId)) {
        blockHeight = parseInt(heightOrId, 10);
        // Get block ID from height using getBlocksById with height
        const headInfo = await provider.getHeadInfo();
        const blocks = await provider.call<{block_items: any[]}>('block_store.get_blocks_by_height', {
          head_block_id: headInfo.head_topology?.id,
          ancestor_start_height: blockHeight,
          num_blocks: 1,
          return_block: true,
          return_receipt: true,
        });
        
        if (!blocks.block_items || blocks.block_items.length === 0) {
          console.error(`\n❌ Block at height ${blockHeight} not found.`);
          return;
        }
        
        const blockItem = blocks.block_items[0];
        const block = blockItem.block;
        const receipt = blockItem.receipt;
        
        console.log('\n📦 Block Information:');
        console.log('─'.repeat(60));
        console.log(`  Height:        ${blockItem.block_height}`);
        console.log(`  Block ID:      ${blockItem.block_id}`);
        console.log(`  Previous:      ${block?.header?.previous}`);
        console.log(`  Timestamp:     ${new Date(parseInt(block?.header?.timestamp || '0')).toISOString()}`);
        console.log(`  Signer:        ${block?.header?.signer}`);
        
        const txCount = block?.transactions?.length || 0;
        console.log(`  Transactions:  ${txCount}`);
        
        if (receipt) {
          console.log(`  Disk Used:     ${receipt.disk_storage_used || 0} bytes`);
          console.log(`  Net Used:      ${receipt.network_bandwidth_used || 0} bytes`);
          console.log(`  Compute Used:  ${receipt.compute_bandwidth_used || 0}`);
        }
        
        if (txCount > 0 && block.transactions) {
          console.log('\n📝 Transactions:');
          console.log('─'.repeat(60));
          
          for (let i = 0; i < block.transactions.length; i++) {
            const tx = block.transactions[i];
            const txId = tx.id || 'unknown';
            const payer = tx.header?.payer || 'unknown';
            const opCount = tx.operations?.length || 0;
            
            console.log(`\n  [${i + 1}] Transaction ID: ${txId}`);
            console.log(`      Payer: ${payer}`);
            console.log(`      Operations: ${opCount}`);
            
            if (options.full && tx.operations) {
              for (let j = 0; j < tx.operations.length; j++) {
                const op = tx.operations[j];
                if (op.call_contract) {
                  console.log(`      - Op ${j + 1}: Call Contract`);
                  console.log(`        Contract: ${op.call_contract.contract_id}`);
                  console.log(`        Entry Point: 0x${op.call_contract.entry_point?.toString(16)}`);
                } else if (op.upload_contract) {
                  console.log(`      - Op ${j + 1}: Upload Contract`);
                }
              }
            }
          }
        }
        
      } else {
        // It's a block ID
        blockId = heightOrId;
        const blocks = await provider.call<{block_items: any[]}>('block_store.get_blocks_by_id', {
          block_ids: [blockId],
          return_block: true,
          return_receipt: true,
        });
        
        if (!blocks.block_items || blocks.block_items.length === 0) {
          console.error(`\n❌ Block with ID ${blockId} not found.`);
          return;
        }
        
        const blockItem = blocks.block_items[0];
        const block = blockItem.block;
        const receipt = blockItem.receipt;
        
        console.log('\n📦 Block Information:');
        console.log('─'.repeat(60));
        console.log(`  Height:        ${blockItem.block_height}`);
        console.log(`  Block ID:      ${blockItem.block_id}`);
        console.log(`  Previous:      ${block?.header?.previous}`);
        console.log(`  Timestamp:     ${new Date(parseInt(block?.header?.timestamp || '0')).toISOString()}`);
        console.log(`  Signer:        ${block?.header?.signer}`);
        
        const txCount = block?.transactions?.length || 0;
        console.log(`  Transactions:  ${txCount}`);
        
        if (receipt) {
          console.log(`  Disk Used:     ${receipt.disk_storage_used || 0} bytes`);
          console.log(`  Net Used:      ${receipt.network_bandwidth_used || 0} bytes`);
          console.log(`  Compute Used:  ${receipt.compute_bandwidth_used || 0}`);
        }
        
        if (txCount > 0 && block.transactions) {
          console.log('\n📝 Transactions:');
          console.log('─'.repeat(60));
          
          for (let i = 0; i < block.transactions.length; i++) {
            const tx = block.transactions[i];
            const txId = tx.id || 'unknown';
            const payer = tx.header?.payer || 'unknown';
            const opCount = tx.operations?.length || 0;
            
            console.log(`\n  [${i + 1}] Transaction ID: ${txId}`);
            console.log(`      Payer: ${payer}`);
            console.log(`      Operations: ${opCount}`);
            
            if (options.full && tx.operations) {
              for (let j = 0; j < tx.operations.length; j++) {
                const op = tx.operations[j];
                if (op.call_contract) {
                  console.log(`      - Op ${j + 1}: Call Contract`);
                  console.log(`        Contract: ${op.call_contract.contract_id}`);
                  console.log(`        Entry Point: 0x${op.call_contract.entry_point?.toString(16)}`);
                } else if (op.upload_contract) {
                  console.log(`      - Op ${j + 1}: Upload Contract`);
                }
              }
            }
          }
        }
      }
      
    } catch (error: any) {
      console.error('\n❌ Error fetching block:', error.message || error);
    }
  });

// Get account balance (KOIN and VHP)
program
  .command('balance')
  .description('Get KOIN, VHP and Mana balance for an address (uses default account from config if not specified)')
  .argument('[address]', 'Koinos address (optional if default account is configured)')
  .action(async (addressArg?: string) => {
    const opts = program.opts();
    const provider = new Provider([opts.rpc]);
    
    // Use provided address or fall back to config default
    const config = loadConfig();
    const address = addressArg || config.defaultAccount;
    
    if (!address) {
      console.error('\n❌ No address provided and no default account configured.');
      console.error('   Usage: kcli balance <address>');
      console.error('   Or set a default account: kcli config --default-account <address>');
      return;
    }
    
    try {
      const koin = getSystemTokenContract(provider, KOIN_CONTRACT);
      const vhp = getSystemTokenContract(provider, VHP_CONTRACT);
      
      const { result: koinResult } = await koin.functions.balance_of({ owner: address });
      const koinBalance = koinResult?.value ? utils.formatUnits(koinResult.value, 8) : '0';
      
      const { result: vhpResult } = await vhp.functions.balance_of({ owner: address });
      const vhpBalance = vhpResult?.value ? utils.formatUnits(vhpResult.value, 8) : '0';
      
      // Get mana (resource credits)
      const rc = await provider.getAccountRc(address);
      const mana = rc ? utils.formatUnits(rc, 8) : '0';
      
      console.log(`\n💰 Balances for ${address}:`);
      console.log(`   KOIN: ${koinBalance}`);
      console.log(`   VHP:  ${vhpBalance}`);
      console.log(`   Mana: ${mana}`);
    } catch (error: any) {
      if (error.message?.includes('system space')) {
        console.log('\n⚠️  Cannot read balance from this RPC endpoint (system contract restriction).');
        console.log('   Try using a local node or an RPC endpoint with full access.');
        console.log('   Use the "rc" command to check available mana instead.');
      } else {
        console.error('Error fetching balance:', error.message || error);
      }
    }
  });

// Get VHP balance
program
  .command('vhp')
  .description('Get VHP (Virtual Hash Power) balance for an address')
  .argument('<address>', 'Koinos address')
  .action(async (address: string) => {
    const opts = program.opts();
    const provider = new Provider([opts.rpc]);
    
    try {
      const vhp = getSystemTokenContract(provider, VHP_CONTRACT);

      const { result } = await vhp.functions.balance_of({ owner: address });
      const balance = result?.value ? utils.formatUnits(result.value, 8) : '0';
      
      console.log(`\n⚡ VHP Balance for ${address}:`);
      console.log(`   ${balance} VHP`);
    } catch (error: any) {
      if (error.message?.includes('system space')) {
        console.log('\n⚠️  Cannot read VHP balance from this RPC endpoint (system contract restriction).');
      } else {
        console.error('Error fetching VHP balance:', error.message || error);
      }
    }
  });

// Get token balance (any KCS-4 token)
program
  .command('token-balance')
  .description('Get balance for any KCS-4 token')
  .argument('<contractId>', 'Token contract address')
  .argument('<address>', 'Koinos address')
  .action(async (contractId: string, address: string) => {
    const opts = program.opts();
    const provider = new Provider([opts.rpc]);
    
    try {
      const token = await getTokenContract(provider, contractId);

      // Get token info
      const [nameResult, symbolResult, decimalsResult, balanceResult] = await Promise.all([
        token.functions.name ? token.functions.name({}) : { result: { value: 'Unknown' } },
        token.functions.symbol ? token.functions.symbol({}) : { result: { value: '???' } },
        token.functions.decimals ? token.functions.decimals({}) : { result: { value: 8 } },
        token.functions.balance_of({ owner: address }),
      ]);

      const name = nameResult.result?.value || 'Unknown';
      const symbol = symbolResult.result?.value || '???';
      const decimals = decimalsResult.result?.value || 8;
      const balance = balanceResult.result?.value 
        ? utils.formatUnits(balanceResult.result.value, decimals) 
        : '0';
      
      console.log(`\n🪙 ${name} (${symbol}) Balance for ${address}:`);
      console.log(`   ${balance} ${symbol}`);
    } catch (error) {
      console.error('Error fetching token balance:', error);
    }
  });

// Generate new wallet
program
  .command('generate-wallet')
  .description('Generate a new Koinos wallet')
  .action(() => {
    // Generate random 32 bytes and use as seed
    const randomBytes = crypto.randomBytes(32).toString('hex');
    const signer = Signer.fromSeed(randomBytes);
    
    console.log('\n🔑 New Wallet Generated:');
    console.log(`  Address: ${signer.getAddress()}`);
    console.log(`  Private Key (WIF): ${signer.getPrivateKey('wif')}`);
    console.log('\n⚠️  IMPORTANT: Save your private key securely!');
  });

// Derive accounts from seed phrase (BIP-39/BIP-44) - Kondor compatible
program
  .command('derive-from-seed')
  .description('Derive the first N accounts from a BIP-39 seed phrase (Kondor compatible)')
  .argument('<seedPhrase>', 'BIP-39 mnemonic seed phrase (12 or 24 words)')
  .option('-n, --num-accounts <number>', 'Number of accounts to derive', '2')
  .action((seedPhrase: string, options: { numAccounts: string }) => {
    try {
      const numAccounts = parseInt(options.numAccounts, 10);
      if (isNaN(numAccounts) || numAccounts < 1 || numAccounts > 100) {
        console.error('\n❌ Invalid number of accounts. Must be between 1 and 100.');
        return;
      }
      
      // Use ethers HDNode (same as Kondor wallet)
      const hdNode = ethers.utils.HDNode.fromMnemonic(seedPhrase);
      
      console.log(`\n🔑 Derived Accounts from Seed Phrase (${numAccounts} accounts):`);
      console.log('─'.repeat(70));
      
      for (let i = 0; i < numAccounts; i++) {
        // Kondor derivation path: m/44'/659'/{accountIndex}'/0/0
        // Each account increments the account index (3rd level), not the address index
        const derivationPath = `m/44'/659'/${i}'/0/0`;
        const derived = hdNode.derivePath(derivationPath);
        
        // Create signer from the derived private key (remove '0x' prefix)
        const signer = new Signer({
          privateKey: derived.privateKey.slice(2),
        });
        
        console.log(`\n  Account #${i + 1} (${derivationPath})`);
        console.log(`    Address:     ${signer.getAddress()}`);
        console.log(`    Private Key: ${signer.getPrivateKey('wif')}`);
      }
      
      console.log('\n' + '─'.repeat(70));
      console.log('⚠️  IMPORTANT: Keep your seed phrase and private keys secure!');
      console.log('    Never share them with anyone.');
      
    } catch (error: any) {
      console.error('\n❌ Error deriving accounts:', error.message || error);
    }
  });

// Get address from private key
program
  .command('address')
  .description('Get address from a private key (WIF)')
  .argument('<privateKey>', 'Private key in WIF format')
  .action((privateKey: string) => {
    try {
      const signer = Signer.fromWif(privateKey);
      console.log(`\n📍 Address: ${signer.getAddress()}`);
    } catch (error) {
      console.error('Invalid private key format');
    }
  });

// Get account nonce
program
  .command('nonce')
  .description('Get account nonce')
  .argument('<address>', 'Koinos address')
  .action(async (address: string) => {
    const opts = program.opts();
    const provider = new Provider([opts.rpc]);
    
    try {
      const nonce = await provider.getNonce(address);
      console.log(`\n🔢 Nonce for ${address}: ${nonce}`);
    } catch (error) {
      console.error('Error fetching nonce:', error);
    }
  });

// Get account RC (Resource Credits)
program
  .command('rc')
  .description('Get account resource credits (mana)')
  .argument('<address>', 'Koinos address')
  .action(async (address: string) => {
    const opts = program.opts();
    const provider = new Provider([opts.rpc]);
    
    try {
      const rc = await provider.getAccountRc(address);
      const rcFormatted = rc ? utils.formatUnits(rc, 8) : '0';
      console.log(`\n⚡ Resource Credits for ${address}:`);
      console.log(`   ${rcFormatted} mana`);
    } catch (error) {
      console.error('Error fetching RC:', error);
    }
  });

// Read contract
program
  .command('read-contract')
  .description('Read a contract method')
  .argument('<contractId>', 'Contract address')
  .argument('<method>', 'Method name to call')
  .option('-a, --args <json>', 'Method arguments as JSON', '{}')
  .action(async (contractId: string, method: string, options: { args: string }) => {
    const opts = program.opts();
    const provider = new Provider([opts.rpc]);
    
    try {
      const contract = await getTokenContract(provider, contractId);
      
      const args = JSON.parse(options.args);
      const { result } = await contract.functions[method](args);
      
      console.log('\n📄 Contract Response:');
      console.log(JSON.stringify(result, null, 2));
    } catch (error) {
      console.error('Error reading contract:', error);
    }
  });

// Import wallet from private key
program
  .command('import-wallet')
  .description('Import a wallet from a private key (WIF format)')
  .argument('<privateKey>', 'Private key in WIF format')
  .action((privateKey: string) => {
    try {
      const signer = Signer.fromWif(privateKey);
      const address = signer.getAddress();
      
      console.log('\n🔐 Setting up wallet encryption...');
      const password = promptNewPassword();
      
      saveWallet(privateKey, address, password);
      
      console.log('\n✅ Wallet imported and encrypted successfully!');
      console.log(`   Address: ${address}`);
      console.log(`   Stored in: ${WALLET_FILE}`);
      console.log('\n⚠️  Remember your password - it cannot be recovered!');
    } catch (error: any) {
      if (error.message === 'Passwords do not match' || error.message.includes('Password must be')) {
        console.error(`❌ ${error.message}`);
      } else {
        console.error('❌ Invalid private key format. Please provide a valid WIF key.');
      }
    }
  });

// Show current wallet
program
  .command('wallet')
  .description('Show the current wallet address')
  .action(() => {
    const walletFile = loadWalletFile();
    if (!walletFile) {
      console.log('\n❌ No wallet found. Import one with: kcli import-wallet <privateKey>');
      return;
    }
    console.log('\n👛 Current Wallet:');
    console.log(`   Address: ${walletFile.address}`);
    console.log(`   Created: ${walletFile.createdAt}`);
    console.log(`   🔐 Encrypted (password required for operations)`);
  });

// Delete wallet
program
  .command('delete-wallet')
  .description('Delete the stored wallet')
  .action(() => {
    if (deleteWallet()) {
      console.log('\n✅ Wallet deleted successfully.');
    } else {
      console.log('\n❌ No wallet found to delete.');
    }
  });

// Register block producer public key to a producer address
program
  .command('register-producer-key')
  .description('Register a block producer public key to a producer address using the PoB contract')
  .argument('<producerAddressOrPublicKey>', 'Producer address or public key (if main producer address is configured)')
  .argument('[publicKey]', 'Block producer public key in base64url format')
  .option('--dry-run', 'Show transaction details without signing or submitting')
  .action(async (producerAddressOrPublicKey: string, publicKeyArg: string | undefined, options: { dryRun?: boolean }) => {
    const opts = program.opts();
    const provider = new Provider([opts.rpc]);
    const config = loadConfig();

    // Support two forms:
    // 1) kcli register-producer-key <producerAddress> <publicKey>
    // 2) kcli register-producer-key <publicKey>  (uses config.mainProducerAddress)
    const producerAddress = publicKeyArg ? producerAddressOrPublicKey : config.mainProducerAddress;
    const publicKey = publicKeyArg || producerAddressOrPublicKey;

    if (!producerAddress) {
      console.log('\n❌ No producer address available.');
      console.log('   Provide it explicitly: kcli register-producer-key <producerAddress> <publicKey>');
      console.log('   Or set it in config: kcli config --main-producer-address <address>');
      return;
    }

    if (!publicKeyArg) {
      console.log(`\nℹ️  Using configured main producer address: ${producerAddress}`);
    }

    // Check if wallet exists
    const walletFile = loadWalletFile();
    if (!walletFile) {
      console.log('\n❌ No wallet found. Import one first with: kcli import-wallet <privateKey>');
      return;
    }

    // Validate producer address
    let isValidProducerAddress = false;
    try {
      isValidProducerAddress = utils.isChecksumAddress(producerAddress);
    } catch (error) {
      isValidProducerAddress = false;
    }

    if (!isValidProducerAddress) {
      console.log('\n❌ Invalid producer address format.');
      return;
    }

    // Validate and inspect public key format
    let publicKeyBytes: Uint8Array;
    try {
      publicKeyBytes = utils.decodeBase64url(publicKey);
    } catch (error) {
      console.log('\n❌ Invalid public key format. Expected base64url encoded key.');
      return;
    }

    if (publicKeyBytes.length !== 33 && publicKeyBytes.length !== 65) {
      console.log('\n❌ Invalid public key length.');
      console.log(`   Decoded length: ${publicKeyBytes.length} bytes`);
      console.log('   Expected: 33 bytes (compressed) or 65 bytes (uncompressed)');
      return;
    }

    // Prompt for password to unlock wallet
    console.log(`\n🔐 Unlocking wallet for address: ${walletFile.address}`);
    const password = promptPassword('Enter wallet password: ');

    let wallet;
    try {
      wallet = loadWallet(password);
      if (!wallet) {
        console.error('❌ Failed to load wallet.');
        return;
      }
    } catch (error: any) {
      console.error('❌ Invalid password. Please try again.');
      return;
    }

    if (wallet.address !== producerAddress) {
      console.log('\n⚠️  Wallet address differs from producer address.');
      console.log(`   Wallet:   ${wallet.address}`);
      console.log(`   Producer: ${producerAddress}`);
      console.log('   This transaction must be authorized by the producer address.');
    }

    try {
      const signer = Signer.fromWif(wallet.privateKey);
      signer.provider = provider;

      const pob = new Contract({
        id: POB_CONTRACT,
        abi: pobAbi,
        provider,
        signer,
      });

      const { operation: registerKeyOp } = await pob.functions.register_public_key({
        producer: producerAddress,
        public_key: publicKey,
      }, { onlyOperation: true });

      const transaction = new Transaction({
        signer,
        provider,
      });

      await transaction.pushOperation(registerKeyOp);
      await transaction.prepare();

      console.log('\n🔗 Producer Key Registration Summary:');
      console.log(`   Producer Address: ${producerAddress}`);
      console.log(`   Public Key: ${publicKey}`);
      console.log(`   Public Key Bytes: ${publicKeyBytes.length}`);
      console.log(`   Signer Address: ${wallet.address}`);

      console.log('\n📝 Transaction Details (BEFORE SIGNING):');
      console.log('─'.repeat(50));
      console.log(`   Transaction ID: ${transaction.transaction.id}`);
      console.log(`   Payer: ${transaction.transaction.header?.payer}`);
      console.log(`   Nonce: ${transaction.transaction.header?.nonce}`);
      console.log(`   RC Limit: ${transaction.transaction.header?.rc_limit}`);
      console.log(`   Contract: ${registerKeyOp.call_contract?.contract_id}`);
      console.log(`   Entry Point: ${registerKeyOp.call_contract?.entry_point}`);
      console.log(`   Args (base64): ${registerKeyOp.call_contract?.args}`);
      console.log('─'.repeat(50));

      if (options.dryRun) {
        console.log('\n📋 Dry run - transaction NOT signed or submitted.');
        return;
      }

      const confirm = readlineSync.question('\n⚠️  Type "REGISTER" to confirm and sign: ');
      if (confirm !== 'REGISTER') {
        console.log('\n❌ Transaction cancelled.');
        return;
      }

      console.log('\n   Signing and submitting transaction...\n');
      await transaction.sign();
      const receipt = await transaction.send();

      console.log('✅ Registration transaction submitted!');
      console.log(`   Transaction ID: ${transaction.transaction.id}`);

      if (receipt) {
        if (receipt.logs && receipt.logs.length > 0) {
          console.log('   Logs:', receipt.logs);
        }
        if (receipt.events && receipt.events.length > 0) {
          console.log(`   Events: ${receipt.events.length} event(s)`);
        }
      }

      console.log('\n⏳ Waiting for transaction to be included in a block...');
      try {
        const blockInfo = await transaction.wait('byTransactionId', 60000);
        console.log(`   ✅ Transaction confirmed in block ${blockInfo?.blockNumber || 'unknown'}`);
      } catch (waitError: any) {
        console.log('   ⚠️  Could not confirm transaction (timeout). It may still be pending.');
      }
    } catch (error: any) {
      console.error('\n❌ Error registering producer key:');
      if (error.message) {
        console.error(`   Message: ${error.message}`);
      }
      if (error.code) {
        console.error(`   Code: ${error.code}`);
      }
      if (error.logs && error.logs.length > 0) {
        console.error(`   Logs: ${JSON.stringify(error.logs)}`);
      }
      if (error.receipt) {
        console.error(`   Receipt: ${JSON.stringify(error.receipt, null, 2)}`);
      }
    }
  });

// Burn KOIN (converts to VHP)
program
  .command('burn')
  .description('Burn KOIN to convert to VHP (specify amount or percentage)')
  .option('-p, --percent <number>', 'Percentage of KOIN to burn')
  .option('-a, --amount <number>', 'Exact amount of KOIN to burn')
  .option('--dry-run', 'Show what would be burned without executing')
  .action(async (options: { percent?: string; amount?: string; dryRun?: boolean }) => {
    const opts = program.opts();
    const provider = new Provider([opts.rpc]);
    
    // Check if wallet exists
    const walletFile = loadWalletFile();
    if (!walletFile) {
      console.log('\n❌ No wallet found. Import one first with: kcli import-wallet <privateKey>');
      return;
    }
    
    // Validate options
    if (!options.percent && !options.amount) {
      console.error('❌ Please specify either --percent (-p) or --amount (-a)');
      console.error('   Examples:');
      console.error('     kcli burn -p 95      # Burn 95% of KOIN balance');
      console.error('     kcli burn -a 10     # Burn exactly 10 KOIN');
      return;
    }
    
    if (options.percent && options.amount) {
      console.error('❌ Cannot specify both --percent and --amount. Choose one.');
      return;
    }
    
    let percent: number | undefined;
    let exactAmount: number | undefined;
    
    if (options.percent) {
      percent = parseFloat(options.percent);
      if (isNaN(percent) || percent <= 0 || percent > 100) {
        console.error('❌ Invalid percentage. Must be between 0 and 100.');
        return;
      }
    }
    
    if (options.amount) {
      exactAmount = parseFloat(options.amount);
      if (isNaN(exactAmount) || exactAmount <= 0) {
        console.error('❌ Invalid amount. Must be a positive number.');
        return;
      }
    }
    
    // Prompt for password to unlock wallet
    console.log(`\n🔐 Unlocking wallet for address: ${walletFile.address}`);
    const password = promptPassword('Enter wallet password: ');
    
    let wallet;
    try {
      wallet = loadWallet(password);
      if (!wallet) {
        console.error('❌ Failed to load wallet.');
        return;
      }
    } catch (error: any) {
      console.error('❌ Invalid password. Please try again.');
      return;
    }
    
    try {
      const signer = Signer.fromWif(wallet.privateKey);
      signer.provider = provider;
      
      // Get KOIN contract
      const koin = new Contract({
        id: KOIN_CONTRACT,
        abi: tokenAbi,
        provider,
        signer,
      });
      
      // Get current balance
      const { result: balanceResult } = await koin.functions.balance_of({ owner: wallet.address });
      const currentBalance = balanceResult?.value ? BigInt(balanceResult.value) : BigInt(0);
      const currentFormatted = utils.formatUnits(currentBalance.toString(), 8);
      
      if (currentBalance === BigInt(0)) {
        console.log('\n❌ No KOIN balance to burn.');
        return;
      }
      
      // Check available mana
      const availableMana = await provider.getAccountRc(wallet.address);
      const manaValue = availableMana ? BigInt(availableMana) : BigInt(0);
      const manaFormatted = utils.formatUnits(manaValue.toString(), 8);
      
      // Estimate required mana (roughly 1 KOIN = 10^8 mana units, transaction needs ~0.1-0.5 mana typically)
      const estimatedManaNeeded = BigInt(50000000); // ~0.5 mana should be enough for approve + burn
      
      if (manaValue < estimatedManaNeeded) {
        console.log(`\n❌ Insufficient mana to execute transaction.`);
        console.log(`   Available Mana: ${manaFormatted}`);
        console.log(`   Estimated Needed: ~0.5`);
        console.log(`\n   💡 Mana regenerates over time based on your KOIN balance.`);
        console.log(`      Wait a few minutes and try again.`);
        return;
      }
      
      // Calculate amount to burn
      let burnAmount: bigint;
      let burnDescription: string;
      
      if (exactAmount !== undefined) {
        // Exact amount specified
        burnAmount = BigInt(Math.floor(exactAmount * 1e8));
        burnDescription = `${exactAmount} KOIN (exact)`;
        
        if (burnAmount > currentBalance) {
          console.log(`\n❌ Insufficient KOIN balance.`);
          console.log(`   Requested: ${exactAmount} KOIN`);
          console.log(`   Available: ${currentFormatted} KOIN`);
          return;
        }
      } else {
        // Percentage specified
        burnAmount = (currentBalance * BigInt(Math.floor(percent! * 100))) / BigInt(10000);
        burnDescription = `${percent}%`;
      }
      
      const remainingAmount = currentBalance - burnAmount;
      
      const burnFormatted = utils.formatUnits(burnAmount.toString(), 8);
      const remainingFormatted = utils.formatUnits(remainingAmount.toString(), 8);
      
      // Get current VHP balance (before burn)
      const vhp = new Contract({
        id: VHP_CONTRACT,
        abi: tokenAbi,
        provider,
      });
      const { result: oldVhpResult } = await vhp.functions.balance_of({ owner: wallet.address });
      const oldVhpBalance = oldVhpResult?.value ? utils.formatUnits(oldVhpResult.value, 8) : '0';
      
      console.log('\n🔥 KOIN Burn Summary:');
      console.log(`   Address: ${wallet.address}`);
      console.log(`   Current KOIN Balance: ${currentFormatted} KOIN`);
      console.log(`   Current VHP Balance: ${oldVhpBalance} VHP`);
      console.log(`   Amount to Burn (${burnDescription}): ${burnFormatted} KOIN`);
      console.log(`   Remaining after Burn: ${remainingFormatted} KOIN`);
      console.log(`   Available Mana: ${manaFormatted}`);
      console.log(`   VHP will be credited to the same address.`);
      
      // Check current allowance for PoB contract (spender)
      let currentAllowance = BigInt(0);
      try {
        const { result: allowanceResult } = await koin.functions.allowance({
          owner: wallet.address,
          spender: POB_CONTRACT,
        });
        currentAllowance = allowanceResult?.value ? BigInt(allowanceResult.value) : BigInt(0);
      } catch (e: any) {
        // No allowance set yet - this is normal, just means we need to approve
        currentAllowance = BigInt(0);
      }
      const allowanceFormatted = utils.formatUnits(currentAllowance.toString(), 8);
      
      console.log(`\n📋 Current Allowance for PoB Contract: ${allowanceFormatted} KOIN`);
      
      const needsApproval = currentAllowance < burnAmount;
      
      if (needsApproval) {
        console.log(`   ⚠️  Insufficient allowance. Need to approve ${burnFormatted} KOIN for PoB contract.`);
      } else {
        console.log(`   ✅ Sufficient allowance for burn.`);
      }
      
      // Get the PoB (Proof of Burn) contract - this is what actually converts KOIN to VHP
      const pob = new Contract({
        id: POB_CONTRACT,
        abi: pobAbi,
        provider,
        signer,
      });
      
      // Build operations
      const operations: { name: string; operation: any }[] = [];
      
      // Add approval operation if needed - approve PoB contract to spend KOIN
      if (needsApproval) {
        const { operation: approveOp } = await koin.functions.approve({
          owner: wallet.address,
          spender: POB_CONTRACT,
          value: burnAmount.toString(),
        }, { onlyOperation: true });
        operations.push({ name: 'approve', operation: approveOp });
      }
      
      // Add burn operation via PoB contract (this burns KOIN and mints VHP)
      const { operation: burnOp } = await pob.functions.burn({
        token_amount: burnAmount.toString(),
        burn_address: wallet.address,
        vhp_address: wallet.address,
      }, { onlyOperation: true });
      operations.push({ name: 'burn (PoB)', operation: burnOp });
      
      // Create transaction manually to inspect before signing
      // Use 10% of available mana as RC limit (should be plenty for approve + burn)
      const rcLimit = (manaValue * BigInt(10)) / BigInt(100);
      const transaction = new Transaction({
        signer,
        provider,
        options: {
          rcLimit: rcLimit.toString(),
        },
      });
      
      // Push all operations
      for (const op of operations) {
        await transaction.pushOperation(op.operation);
      }
      await transaction.prepare();
      
      // Show transaction details before signing
      console.log('\n📝 Transaction Details (BEFORE SIGNING):');
      console.log('─'.repeat(50));
      console.log(`   Transaction ID: ${transaction.transaction.id}`);
      console.log(`   Payer: ${transaction.transaction.header?.payer}`);
      console.log(`   Payee: ${transaction.transaction.header?.payee || '(none)'}`);
      console.log(`   Nonce: ${transaction.transaction.header?.nonce}`);
      console.log(`   RC Limit: ${transaction.transaction.header?.rc_limit}`);
      console.log(`   Chain ID: ${transaction.transaction.header?.chain_id}`);
      console.log(`\n   Operations (${operations.length}):`);
      transaction.transaction.operations?.forEach((op, i) => {
        const opName = operations[i]?.name || 'unknown';
        console.log(`   [${i + 1}] ${opName.toUpperCase()}`);
        console.log(`       Contract: ${op.call_contract?.contract_id}`);
        console.log(`       Entry Point: ${op.call_contract?.entry_point}`);
        console.log(`       Args (base64): ${op.call_contract?.args}`);
      });
      console.log('─'.repeat(50));
      
      // Decoded operation details
      console.log('\n   Decoded Operations:');
      if (needsApproval) {
        console.log(`   1. APPROVE:`);
        console.log(`       Owner: ${wallet.address}`);
        console.log(`       Spender: ${POB_CONTRACT} (PoB Contract)`);
        console.log(`       Amount: ${burnFormatted} KOIN`);
      }
      console.log(`   ${needsApproval ? '2' : '1'}. BURN (via PoB Contract):`);
      console.log(`       Contract: ${POB_CONTRACT} (Proof of Burn)`);
      console.log(`       Token Amount: ${burnFormatted} KOIN`);
      console.log(`       Burn Address: ${wallet.address}`);
      console.log(`       VHP Address: ${wallet.address}`);
      console.log('─'.repeat(50));
      
      if (options.dryRun) {
        console.log('\n📋 Dry run - transaction NOT signed or submitted.');
        return;
      }
      
      // Confirm with user
      console.log('\n⚠️  This action is IRREVERSIBLE!');
      const confirm = readlineSync.question('   Type "BURN" to confirm and sign: ');
      
      if (confirm !== 'BURN') {
        console.log('\n❌ Transaction cancelled.');
        return;
      }
      
      console.log('\n   Signing and submitting transaction...\n');
      
      // Sign and send
      await transaction.sign();
      const receipt = await transaction.send();
      
      console.log('✅ Burn transaction submitted!');
      console.log(`   Transaction ID: ${transaction.transaction.id}`);
      
      if (receipt) {
        if (receipt.logs && receipt.logs.length > 0) {
          console.log('   Logs:', receipt.logs);
        }
        if (receipt.events && receipt.events.length > 0) {
          console.log(`   Events: ${receipt.events.length} event(s)`);
        }
      }
      
      // Wait for transaction to be mined
      console.log('\n⏳ Waiting for transaction to be included in a block...');
      try {
        const blockInfo = await transaction.wait('byTransactionId', 60000);
        console.log(`   ✅ Transaction confirmed in block ${blockInfo?.blockNumber || 'unknown'}`);
      } catch (waitError: any) {
        console.log(`   ⚠️  Could not confirm transaction (timeout). Balances may not be updated yet.`);
      }
      
      // Get new balances
      const { result: newKoinResult } = await koin.functions.balance_of({ owner: wallet.address });
      const newKoinBalance = newKoinResult?.value ? utils.formatUnits(newKoinResult.value, 8) : '0';
      
      const { result: newVhpResult } = await vhp.functions.balance_of({ owner: wallet.address });
      const newVhpBalance = newVhpResult?.value ? utils.formatUnits(newVhpResult.value, 8) : '0';
      
      console.log('\n📊 Balance Comparison:');
      console.log('   ┌────────────┬───────────────────────┬───────────────────────┐');
      console.log('   │ Token      │ Before                │ After                 │');
      console.log('   ├────────────┼───────────────────────┼───────────────────────┤');
      console.log(`   │ KOIN       │ ${currentFormatted.padEnd(21)} │ ${newKoinBalance.padEnd(21)} │`);
      console.log(`   │ VHP        │ ${oldVhpBalance.padEnd(21)} │ ${newVhpBalance.padEnd(21)} │`);
      console.log('   └────────────┴───────────────────────┴───────────────────────┘');
      
    } catch (error: any) {
      console.error('\n❌ Error burning KOIN:');
      if (error.message) {
        console.error(`   Message: ${error.message}`);
      }
      if (error.code) {
        console.error(`   Code: ${error.code}`);
      }
      if (error.logs && error.logs.length > 0) {
        console.error(`   Logs: ${JSON.stringify(error.logs)}`);
      }
      if (error.receipt) {
        console.error(`   Receipt: ${JSON.stringify(error.receipt, null, 2)}`);
      }
      // Full error for debugging
      console.error(`   Full error: ${JSON.stringify(error)}`);
    }
  });

// Config command
program
  .command('config')
  .description('View or set configuration options')
  .option('--default-account <address>', 'Set the default account address')
  .option('--main-producer-address <address>', 'Set the main producer address used by register-producer-key')
  .option('--show', 'Show current configuration')
  .action(async (options: { defaultAccount?: string; mainProducerAddress?: string; show?: boolean }) => {
    const config = loadConfig();
    
    if (options.defaultAccount) {
      config.defaultAccount = options.defaultAccount;
      saveConfig(config);
      console.log(`\n✅ Default account set to: ${options.defaultAccount}`);
      return;
    }

    if (options.mainProducerAddress) {
      if (!utils.isChecksumAddress(options.mainProducerAddress)) {
        console.log('\n❌ Invalid main producer address format.');
        return;
      }
      config.mainProducerAddress = options.mainProducerAddress;
      saveConfig(config);
      console.log(`\n✅ Main producer address set to: ${options.mainProducerAddress}`);
      return;
    }
    
    if (options.show || (!options.defaultAccount && !options.mainProducerAddress)) {
      console.log('\n⚙️  Current Configuration:');
      console.log(`   Config file: ${CONFIG_FILE}`);
      console.log(`   Default Account: ${config.defaultAccount || '(not set)'}`);
      console.log(`   Main Producer Address: ${config.mainProducerAddress || '(not set)'}`);
      console.log(`   RPC: ${config.rpc || DEFAULT_RPC + ' (default)'}`);
    }
  });

program.parse();
