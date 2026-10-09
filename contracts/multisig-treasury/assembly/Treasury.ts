// SPDX-License-Identifier: MIT
// Koinos multisig treasury, contract template 1.0.0.
// One account controlled by a quorum of distinct owner keys. It can only make single KOIN transfers and
// replace its own owner policy; its code, ABI and authority flags can never be replaced after the upload.
import { Arrays, authority, Crypto, kcs4, Protobuf, protocol, Storage, System, value } from "@koinos/sdk-as";
import { treasury } from "./proto/treasury";
import { DEPLOYMENT_CHAIN_ID, DEPLOYMENT_KOIN, DEPLOYMENT_OWNER_COUNT, DEPLOYMENT_OWNERS, DEPLOYMENT_THRESHOLD, DEPLOYMENT_TREASURY } from "./Deployment";

export const TEMPLATE_NAME = "koinos-multisig-treasury";
export const TEMPLATE_VERSION = "1.0.0";
export const MIN_OWNERS: u32 = 3;
export const MAX_OWNERS: u32 = 15;
export const TRANSFER_ENTRY_POINT: u32 = 0x27f576ca;   // sha256("transfer")[0:4], KCS-4
export const SET_POLICY_ENTRY_POINT: u32 = 0x1429285f; // sha256("set_policy")[0:4]
const POLICY_SPACE_ID: u32 = 0;
// 15 signatures with protobuf framing exceed the SDK's default 1 KB system-call buffer.
const SYSTEM_BUFFER_SIZE: u32 = 8192;

/// Lexicographic byte order; owner lists must be strictly ascending (unique and canonical).
function compareBytes(a: Uint8Array, b: Uint8Array): i32 {
  const n = a.length < b.length ? a.length : b.length;
  for (let i = 0; i < n; i++) if (a[i] != b[i]) return (a[i] as i32) - (b[i] as i32);
  return a.length - b.length;
}

/// Build inputs are raw bytes; addresses are never decoded inside the contract.
function bytesOf(source: StaticArray<u8>, offset: i32, length: i32): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = source[offset + i];
  return out;
}

function contains(list: Uint8Array[], item: Uint8Array): bool {
  for (let i = 0; i < list.length; i++) if (Arrays.equal(list[i], item)) return true;
  return false;
}

export class Treasury {
  contractId: Uint8Array = System.getContractId();
  treasury: Uint8Array = bytesOf(DEPLOYMENT_TREASURY, 0, DEPLOYMENT_TREASURY.length);
  koin: Uint8Array = bytesOf(DEPLOYMENT_KOIN, 0, DEPLOYMENT_KOIN.length);
  policyStore: Storage.Obj<treasury.policy_object> = new Storage.Obj<treasury.policy_object>(
    this.contractId,
    POLICY_SPACE_ID,
    treasury.policy_object.decode,
    treasury.policy_object.encode
  );

  constructor() {
    System.setSystemBufferSize(SYSTEM_BUFFER_SIZE);
  }

  /// Called only by the kernel. Read-only: never writes state or consumes anything.
  authorize(args: authority.authorize_arguments): authority.authorize_result {
    return new authority.authorize_result(this.authorized(args));
  }

  private authorized(args: authority.authorize_arguments): bool {
    // Code, ABI and override flags are immutable: no key and no quorum may upload again.
    if (args.type == authority.authorization_type.contract_upload) return false;
    if (args.type != authority.authorization_type.contract_call && args.type != authority.authorization_type.transaction_application) return false;
    const policy = this.currentPolicy();
    if (policy == null) return false;
    const op = this.singleOperation();
    if (op == null) return false;
    if (args.type == authority.authorization_type.contract_call) {
      // Only the pinned KOIN contract, called directly by this transaction's single operation, asking for
      // transfer authority. Allowances, burns, other contracts and nested callers are refused.
      const call = args.call;
      if (call == null || !this.isKoinTransfer(op)) return false;
      if (!Arrays.equal(call.contract_id, this.koin) || call.entry_point != TRANSFER_ENTRY_POINT || call.caller.length != 0) return false;
      if (!Arrays.equal(call.data, op.call_contract!.args)) return false;
    } else if (!this.isKoinTransfer(op) && !this.isPolicyUpdate(op)) {
      // Treasury Mana pays only for its own reviewed operations.
      return false;
    }
    return this.quorum(policy);
  }

  /// Replace the whole policy. The current quorum is checked here directly (never through checkAuthority on this
  /// account, which would recurse into authorize). The transaction must be the treasury's own single operation.
  set_policy(args: treasury.set_policy_arguments): treasury.empty_object {
    System.require(System.getCaller().caller.length == 0, "set_policy must be the transaction's operation");
    const policy = this.currentPolicy();
    System.require(policy != null, "stored policy is invalid");
    const op = this.singleOperation();
    System.require(op != null && this.isPolicyUpdate(op) && Arrays.equal(op.call_contract!.args, System.getArguments().args), "invalid policy transaction envelope");
    System.require(this.quorum(policy!), "current owner quorum not met");
    System.require(policy!.version < u64.MAX_VALUE, "policy version exhausted");
    const next = new treasury.policy_object(args.owners, args.threshold, policy!.version + 1);
    this.policyStore.put(next);
    System.event("treasury.policy_updated", Protobuf.encode(next, treasury.policy_object.encode), args.owners);
    return new treasury.empty_object();
  }

  get_policy(args: treasury.get_policy_arguments): treasury.policy_object {
    const policy = this.currentPolicy();
    System.require(policy != null, "stored policy is invalid");
    return policy!;
  }

  get_template(args: treasury.get_template_arguments): treasury.template_info {
    return new treasury.template_info(TEMPLATE_NAME, TEMPLATE_VERSION, this.chainId(), this.koin, MIN_OWNERS, MAX_OWNERS);
  }

  /// The stored policy, or the build-time initial policy before the first update. Null if invalid or if this
  /// artifact runs at any address other than the one it was built for (fail closed).
  private currentPolicy(): treasury.policy_object | null {
    if (!Arrays.equal(this.contractId, this.treasury)) return null;
    let policy = this.policyStore.get();
    if (policy == null) {
      const owners: Uint8Array[] = [];
      if (DEPLOYMENT_OWNERS.length != DEPLOYMENT_OWNER_COUNT * 25) return null;
      for (let i = 0; i < DEPLOYMENT_OWNER_COUNT; i++) owners.push(bytesOf(DEPLOYMENT_OWNERS, i * 25, 25));
      policy = new treasury.policy_object(owners, DEPLOYMENT_THRESHOLD, 0);
    }
    return this.validPolicy(policy.owners, policy.threshold) ? policy : null;
  }

  private chainId(): Uint8Array {
    return bytesOf(DEPLOYMENT_CHAIN_ID, 0, DEPLOYMENT_CHAIN_ID.length);
  }

  /// The only accepted envelope: the bound chain, the treasury pays its own Mana, no payee (the treasury nonce is
  /// the replay domain) and exactly one operation.
  private singleOperation(): protocol.operation | null {
    if (!Arrays.equal(System.getChainId(), this.chainId())) return null;
    const payer = System.getTransactionField("header.payer");
    if (payer == null || !Arrays.equal(payer.bytes_value, this.contractId)) return null;
    const payee = System.getTransactionField("header.payee");
    if (payee == null || payee.bytes_value.length != 0) return null;
    const ops = System.getTransactionField("operations");
    if (ops == null || ops.message_value == null || ops.message_value!.value == null) return null;
    const list = Protobuf.decode<value.list_type>(ops.message_value!.value!, value.list_type.decode);
    if (list.values.length != 1) return null;
    const packed = list.values[0].message_value;
    if (packed == null || packed.value == null) return null;
    return Protobuf.decode<protocol.operation>(packed.value!, protocol.operation.decode);
  }

  /// One canonical KOIN transfer from the treasury: positive amount, valid recipient other than itself, no memo.
  private isKoinTransfer(op: protocol.operation): bool {
    const c = op.call_contract;
    if (c == null || !Arrays.equal(c.contract_id, this.koin) || c.entry_point != TRANSFER_ENTRY_POINT) return false;
    const t = Protobuf.decode<kcs4.transfer_arguments>(c.args, kcs4.transfer_arguments.decode);
    // Canonical bytes only: unknown fields or alternative encodings cannot hide in the signed arguments.
    if (!Arrays.equal(Protobuf.encode(t, kcs4.transfer_arguments.encode), c.args)) return false;
    return Arrays.equal(t.from, this.contractId) && this.isValidAddress(t.to) && !Arrays.equal(t.to, this.contractId)
      && t.value > 0 && t.memo.length == 0;
  }

  /// A canonical set_policy call on this treasury carrying a fully valid replacement policy.
  private isPolicyUpdate(op: protocol.operation): bool {
    const c = op.call_contract;
    if (c == null || !Arrays.equal(c.contract_id, this.contractId) || c.entry_point != SET_POLICY_ENTRY_POINT) return false;
    const p = Protobuf.decode<treasury.set_policy_arguments>(c.args, treasury.set_policy_arguments.decode);
    if (!Arrays.equal(Protobuf.encode(p, treasury.set_policy_arguments.encode), c.args)) return false;
    return this.validPolicy(p.owners, p.threshold);
  }

  /// 3-15 distinct valid owner addresses in ascending byte order, none of them the treasury; a majority threshold
  /// of at least two that stays below the owner count (one owner may be unavailable).
  private validPolicy(owners: Uint8Array[], threshold: u32): bool {
    const n = owners.length as u32;
    if (n < MIN_OWNERS || n > MAX_OWNERS) return false;
    if (threshold < 2 || threshold <= n / 2 || threshold >= n) return false;
    for (let i = 0; i < owners.length; i++) {
      if (!this.isValidAddress(owners[i]) || Arrays.equal(owners[i], this.contractId)) return false;
      if (i > 0 && compareBytes(owners[i - 1], owners[i]) >= 0) return false;
    }
    return true;
  }

  /// Every signature must recover to a distinct current owner, and at least `threshold` of them must be present.
  /// Identities are counted, not signatures: a second signature by the same key refuses the transaction.
  private quorum(policy: treasury.policy_object): bool {
    const field = System.getTransactionField("signatures");
    if (field == null || field.message_value == null || field.message_value!.value == null) return false;
    const signatures = Protobuf.decode<value.list_type>(field.message_value!.value!, value.list_type.decode).values;
    if (signatures.length == 0 || signatures.length > policy.owners.length) return false;
    const id = System.getTransactionField("id");
    if (id == null) return false;
    const signers: Uint8Array[] = [];
    for (let i = 0; i < signatures.length; i++) {
      const signature = signatures[i].bytes_value;
      if (signature.length != 65) return false;
      // The kernel refuses noncanonical or invalid signatures (the whole check fails closed).
      const key = System.recoverPublicKey(signature, id.bytes_value);
      if (key == null) return false;
      const signer = Crypto.addressFromPublicKey(key);
      if (!contains(policy.owners, signer) || contains(signers, signer)) return false;
      signers.push(signer);
    }
    return (signers.length as u32) >= policy.threshold;
  }

  /// Koinos address: 25 bytes = 0x00 + 20-byte hash + 4-byte checksum (first 4 bytes of sha256(sha256(first 21))).
  private isValidAddress(a: Uint8Array): bool {
    if (a.length != 25 || a[0] != 0) return false;
    const h1 = System.hash(Crypto.multicodec.sha2_256, a.slice(0, 21))!;
    const h2 = System.hash(Crypto.multicodec.sha2_256, h1.slice(2))!; // multihash: skip 0x12 0x20
    for (let i = 0; i < 4; i++) if (a[21 + i] != h2[2 + i]) return false;
    return true;
  }
}
