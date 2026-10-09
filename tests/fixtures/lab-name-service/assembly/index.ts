import { System } from "@koinos/sdk-as";

// LAB ONLY (never deployed on a public chain). Stand-in for the name-service system call on a private chain:
// every name resolves to an all-zero address, so KOIN's Mainnet get_account_rc logic treats no account as
// governance and Mana is KOIN-backed exactly as on Mainnet.
export function main(): i32 {
  const result = new Uint8Array(29);
  result[0] = 0x0a; result[1] = 27; // get_address_result.value (address_record)
  result[2] = 0x0a; result[3] = 25; // address_record.address: 25 zero bytes
  System.exit(0, result);
  return 0;
}

main();
