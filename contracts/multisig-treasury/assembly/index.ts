import { authority, Protobuf, System } from "@koinos/sdk-as";
import { Treasury as ContractClass } from "./Treasury";
import { treasury as ProtoNamespace } from "./proto/treasury";

export function main(): i32 {
  const contractArgs = System.getArguments();
  let retbuf = new Uint8Array(1024);

  const c = new ContractClass();

  switch (contractArgs.entry_point) {
    case 0x4a2dbd90: {
      const args = Protobuf.decode<authority.authorize_arguments>(contractArgs.args, authority.authorize_arguments.decode);
      const res = c.authorize(args);
      retbuf = Protobuf.encode(res, authority.authorize_result.encode);
      break;
    }

    case 0x1429285f: {
      const args = Protobuf.decode<ProtoNamespace.set_policy_arguments>(contractArgs.args, ProtoNamespace.set_policy_arguments.decode);
      const res = c.set_policy(args);
      retbuf = Protobuf.encode(res, ProtoNamespace.empty_object.encode);
      break;
    }

    case 0x049c5664: {
      const args = Protobuf.decode<ProtoNamespace.get_policy_arguments>(contractArgs.args, ProtoNamespace.get_policy_arguments.decode);
      const res = c.get_policy(args);
      retbuf = Protobuf.encode(res, ProtoNamespace.policy_object.encode);
      break;
    }

    case 0x99eb59af: {
      const args = Protobuf.decode<ProtoNamespace.get_template_arguments>(contractArgs.args, ProtoNamespace.get_template_arguments.decode);
      const res = c.get_template(args);
      retbuf = Protobuf.encode(res, ProtoNamespace.template_info.encode);
      break;
    }

    default:
      System.exit(1);
      break;
  }

  System.exit(0, retbuf);
  return 0;
}

main();
