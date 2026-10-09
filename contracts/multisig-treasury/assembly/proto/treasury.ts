import { Writer, Reader } from "as-proto";

export namespace treasury {
  export class set_policy_arguments {
    static encode(message: set_policy_arguments, writer: Writer): void {
      const unique_name_owners = message.owners;
      if (unique_name_owners.length !== 0) {
        for (let i = 0; i < unique_name_owners.length; ++i) {
          writer.uint32(10);
          writer.bytes(unique_name_owners[i]);
        }
      }

      if (message.threshold != 0) {
        writer.uint32(16);
        writer.uint32(message.threshold);
      }
    }

    static decode(reader: Reader, length: i32): set_policy_arguments {
      const end: usize = length < 0 ? reader.end : reader.ptr + length;
      const message = new set_policy_arguments();

      while (reader.ptr < end) {
        const tag = reader.uint32();
        switch (tag >>> 3) {
          case 1:
            message.owners.push(reader.bytes());
            break;

          case 2:
            message.threshold = reader.uint32();
            break;

          default:
            reader.skipType(tag & 7);
            break;
        }
      }

      return message;
    }

    owners: Array<Uint8Array>;
    threshold: u32;

    constructor(owners: Array<Uint8Array> = [], threshold: u32 = 0) {
      this.owners = owners;
      this.threshold = threshold;
    }
  }

  @unmanaged
  export class get_policy_arguments {
    static encode(message: get_policy_arguments, writer: Writer): void {}

    static decode(reader: Reader, length: i32): get_policy_arguments {
      const end: usize = length < 0 ? reader.end : reader.ptr + length;
      const message = new get_policy_arguments();

      while (reader.ptr < end) {
        const tag = reader.uint32();
        switch (tag >>> 3) {
          default:
            reader.skipType(tag & 7);
            break;
        }
      }

      return message;
    }

    constructor() {}
  }

  @unmanaged
  export class get_template_arguments {
    static encode(message: get_template_arguments, writer: Writer): void {}

    static decode(reader: Reader, length: i32): get_template_arguments {
      const end: usize = length < 0 ? reader.end : reader.ptr + length;
      const message = new get_template_arguments();

      while (reader.ptr < end) {
        const tag = reader.uint32();
        switch (tag >>> 3) {
          default:
            reader.skipType(tag & 7);
            break;
        }
      }

      return message;
    }

    constructor() {}
  }

  @unmanaged
  export class empty_object {
    static encode(message: empty_object, writer: Writer): void {}

    static decode(reader: Reader, length: i32): empty_object {
      const end: usize = length < 0 ? reader.end : reader.ptr + length;
      const message = new empty_object();

      while (reader.ptr < end) {
        const tag = reader.uint32();
        switch (tag >>> 3) {
          default:
            reader.skipType(tag & 7);
            break;
        }
      }

      return message;
    }

    constructor() {}
  }

  export class policy_object {
    static encode(message: policy_object, writer: Writer): void {
      const unique_name_owners = message.owners;
      if (unique_name_owners.length !== 0) {
        for (let i = 0; i < unique_name_owners.length; ++i) {
          writer.uint32(10);
          writer.bytes(unique_name_owners[i]);
        }
      }

      if (message.threshold != 0) {
        writer.uint32(16);
        writer.uint32(message.threshold);
      }

      if (message.version != 0) {
        writer.uint32(24);
        writer.uint64(message.version);
      }
    }

    static decode(reader: Reader, length: i32): policy_object {
      const end: usize = length < 0 ? reader.end : reader.ptr + length;
      const message = new policy_object();

      while (reader.ptr < end) {
        const tag = reader.uint32();
        switch (tag >>> 3) {
          case 1:
            message.owners.push(reader.bytes());
            break;

          case 2:
            message.threshold = reader.uint32();
            break;

          case 3:
            message.version = reader.uint64();
            break;

          default:
            reader.skipType(tag & 7);
            break;
        }
      }

      return message;
    }

    owners: Array<Uint8Array>;
    threshold: u32;
    version: u64;

    constructor(
      owners: Array<Uint8Array> = [],
      threshold: u32 = 0,
      version: u64 = 0
    ) {
      this.owners = owners;
      this.threshold = threshold;
      this.version = version;
    }
  }

  export class template_info {
    static encode(message: template_info, writer: Writer): void {
      const unique_name_name = message.name;
      if (unique_name_name !== null) {
        writer.uint32(10);
        writer.string(unique_name_name);
      }

      const unique_name_version = message.version;
      if (unique_name_version !== null) {
        writer.uint32(18);
        writer.string(unique_name_version);
      }

      const unique_name_chain_id = message.chain_id;
      if (unique_name_chain_id !== null) {
        writer.uint32(26);
        writer.bytes(unique_name_chain_id);
      }

      const unique_name_koin_contract = message.koin_contract;
      if (unique_name_koin_contract !== null) {
        writer.uint32(34);
        writer.bytes(unique_name_koin_contract);
      }

      if (message.min_owners != 0) {
        writer.uint32(40);
        writer.uint32(message.min_owners);
      }

      if (message.max_owners != 0) {
        writer.uint32(48);
        writer.uint32(message.max_owners);
      }
    }

    static decode(reader: Reader, length: i32): template_info {
      const end: usize = length < 0 ? reader.end : reader.ptr + length;
      const message = new template_info();

      while (reader.ptr < end) {
        const tag = reader.uint32();
        switch (tag >>> 3) {
          case 1:
            message.name = reader.string();
            break;

          case 2:
            message.version = reader.string();
            break;

          case 3:
            message.chain_id = reader.bytes();
            break;

          case 4:
            message.koin_contract = reader.bytes();
            break;

          case 5:
            message.min_owners = reader.uint32();
            break;

          case 6:
            message.max_owners = reader.uint32();
            break;

          default:
            reader.skipType(tag & 7);
            break;
        }
      }

      return message;
    }

    name: string | null;
    version: string | null;
    chain_id: Uint8Array | null;
    koin_contract: Uint8Array | null;
    min_owners: u32;
    max_owners: u32;

    constructor(
      name: string | null = null,
      version: string | null = null,
      chain_id: Uint8Array | null = null,
      koin_contract: Uint8Array | null = null,
      min_owners: u32 = 0,
      max_owners: u32 = 0
    ) {
      this.name = name;
      this.version = version;
      this.chain_id = chain_id;
      this.koin_contract = koin_contract;
      this.min_owners = min_owners;
      this.max_owners = max_owners;
    }
  }
}
