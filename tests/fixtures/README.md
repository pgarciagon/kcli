# Vortex ABI Fixture

`vortex-fresh.abi.json` is the exact public ABI output of the reviewed
fresh-initializer derivative of `VortexBridge/vortex-bridge-v2` at
`42b0ab20653047ec0275c3130accf9210ce4b822` (MIT licensed). It contains no private
identities or keys. ABI SHA-256:
`0810d36e1130a34a8ebfc16a2bb73f58cc00a65dd102fd7a2516017b619ee234`.

Initializer patch SHA-256:
`9f999b2b4561af7062247a6bf47a47790f0c5d9cabdf548788651955136dcd72`.
See `VORTEX_IMPLEMENTATION_STATUS.md` for the corresponding source/Wasm hashes.
This is not unmodified upstream migration bytecode or a deployment approval.
The upstream MIT notice is retained in `VORTEX_LICENSE.txt`.

Tests compare the actual binary descriptor's snake-case fields and wire
encoding to the independently restricted CLI adapter. Do not replace this with
a generated fixture based only on the adapter being tested.
