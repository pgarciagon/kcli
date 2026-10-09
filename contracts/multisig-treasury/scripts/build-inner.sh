#!/bin/bash
# Reproducible build of one personalized treasury artifact. Runs INSIDE the pinned builder (see README):
#   - toolchain = the locked dependencies of koinos/koinos-contracts-as@4fc33bb contracts/koin (the KOIN build tree),
#     installed with --frozen-lockfile --ignore-scripts, mounted read-only at $TOOLCHAIN
#   - protoc 3.21.12 (Debian)
# usage (always through the launcher): build.sh <source dir> <deployment inputs json> <output dir>
# The output dir receives contract.wasm, treasury.abi, Deployment.ts (the generated inputs) and artifact.json.
set -euo pipefail
# Started only by build.sh through `env -i` and `bash --noprofile --norc -p`: no inherited variables, exported
# functions or startup files reach this script. Defense in depth: refuse if any of them is present anyway.
[ -z "${BASH_ENV:-}" ] && [ -z "${ENV:-}" ] && [ -z "$(declare -F)" ] || { echo "unclean shell environment; run build.sh, not this file"; exit 1; }
for name in $(compgen -e); do
  case "$name" in PATH|HOME|LANG|TOOLCHAIN|KOINOS_PROTO|PWD|SHLVL|OLDPWD|_) ;; *) echo "unexpected environment variable $name"; exit 1;; esac
done
[ "$PATH" = /usr/local/bin:/usr/bin:/bin ] && [ "$HOME" = /nonexistent ] && [ "$LANG" = C.UTF-8 ] || { echo "unexpected base environment"; exit 1; }
SRC=$(cd "${1:?source dir}" && pwd); INPUTS=${2:?deployment inputs}; OUT=${3:?output dir}
TOOLCHAIN=${TOOLCHAIN:-/lab/kca-4fc33bb/contracts/koin/node_modules}
KOINOS_PROTO=${KOINOS_PROTO:-/lab/kca-4fc33bb}
# Content pins: the complete installed toolchain tree (scripts/tree-hash.cjs) and the imported Koinos options.
# A different compiler/SDK tree refuses to build instead of producing an artifact that claims this toolchain.
TOOLCHAIN_TREE_SHA256=e5289f1f492a33c4f6d22ae5eef49df1f9041c58f9d5990922855aeda587d9c5
OPTIONS_PROTO_SHA256=7899669e545f7e22d4bb07818428437e71dbdc35ebf2f75be353c62f04bab6fd
# Paths that end up inside generated shell code must be plain: absolute, letters/digits/._/- only (no $, `, quotes).
for path_value in "$TOOLCHAIN" "$KOINOS_PROTO"; do
  case "$path_value" in /*) ;; *) echo "toolchain paths must be absolute"; exit 1;; esac
  case "$path_value" in *[!A-Za-z0-9._/-]*) echo "toolchain path contains unsupported characters"; exit 1;; esac
done
[ -d "$TOOLCHAIN/@koinos/sdk-as" ] && [ -f "$KOINOS_PROTO/koinos/options.proto" ] || { echo "pinned toolchain missing"; exit 1; }
[ "$(protoc --version)" = "libprotoc 3.21.12" ] || { echo "protoc must be 3.21.12"; exit 1; }
# Integrity FIRST: nothing from the toolchain is loaded or executed before its whole tree matches the pin.
# (tree-hash.cjs only lstat()s and reads bytes; symlinks are hashed as links, never followed.)
[ "$(node "$SRC/scripts/tree-hash.cjs" "$TOOLCHAIN" | cut -d' ' -f1)" = "$TOOLCHAIN_TREE_SHA256" ] || { echo "toolchain tree differs from the pinned content hash"; exit 1; }
[ "$(sha256sum "$KOINOS_PROTO/koinos/options.proto" | cut -d' ' -f1)" = "$OPTIONS_PROTO_SHA256" ] || { echo "koinos/options.proto differs from the pinned hash"; exit 1; }
# Versions as plain JSON (never require()), paths passed as arguments, never interpolated into code.
for p in @koinos/sdk-as:1.3.0 assemblyscript:0.27.29 @koinos/proto-as:2.2.0 as-proto:1.0.1 @koinos/as-proto-gen:1.0.0; do
  [ "$(node -e 'const fs = require("fs"); process.stdout.write(JSON.parse(fs.readFileSync(process.argv[1], "utf8")).version)' "$TOOLCHAIN/${p%%:*}/package.json")" = "${p##*:}" ] || { echo "unexpected toolchain version ${p%%:*}"; exit 1; }
done
[ ! -e "$OUT" ] || { echo "output dir exists; refuse overwrite"; exit 1; }
mkdir -p "$OUT"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# The SDK's protobuf plugin reads their request with readFileSync(stdin), which can fail with EAGAIN on a
# non-blocking pipe (a known Node race). Wrap them so the request is buffered in a file first; output is unchanged.
mkdir -p "$WORK/bin"
for P in as-proto-gen:@koinos/as-proto-gen/bin/as-proto-gen; do
  printf '#!/bin/sh\nt=$(mktemp) || exit 1\ncat > "$t" && node "%s" < "$t"; rc=$?\nrm -f "$t"; exit $rc\n' "$TOOLCHAIN/${P#*:}" > "$WORK/bin/${P%%:*}"
  chmod +x "$WORK/bin/${P%%:*}"
done

# 1. Validate the public deployment inputs and render assembly/Deployment.ts (no secrets are ever inputs).
node "$SRC/scripts/render-inputs.cjs" "$INPUTS" "$WORK/Deployment.ts" "$WORK/inputs.canonical.json"

# 2. Two clean builds from the same sources must produce the same bytes.
build() { # <dir>
  local d=$1
  mkdir -p "$d"; cp -a "$SRC/assembly" "$SRC/asconfig.json" "$d/"; cp "$WORK/Deployment.ts" "$d/assembly/Deployment.ts"
  ln -sfn "$TOOLCHAIN" "$d/node_modules"; mkdir -p "$d/abi"
  # generated protobuf classes and ABI must equal the reviewed copies in the source tree
  (cd "$d" && protoc -I. -I"$KOINOS_PROTO" --plugin=protoc-gen-as="$WORK/bin/as-proto-gen" --as_out=. assembly/proto/treasury.proto)
  cmp -s "$d/assembly/proto/treasury.ts" "$SRC/assembly/proto/treasury.ts" || { echo "generated proto/treasury.ts differs from the reviewed copy"; exit 1; }
  (cd "$d" && protoc -I. -I"$KOINOS_PROTO" --include_imports --descriptor_set_out=abi/treasury.pb assembly/proto/treasury.proto)
  node "$SRC/scripts/make-abi.cjs" "$d/abi/treasury.pb" "$d/abi/treasury.abi"
  (cd "$d" && node node_modules/assemblyscript/bin/asc.js assembly/index.ts --target release --use abort= --use BUILD_FOR_TESTING=0 --disable sign-extension --config asconfig.json >/dev/null)
}
build "$WORK/a"; build "$WORK/b"
A=$(sha256sum "$WORK/a/build/release/contract.wasm" | cut -d' ' -f1); B=$(sha256sum "$WORK/b/build/release/contract.wasm" | cut -d' ' -f1)
[ "$A" = "$B" ] || { echo "non-deterministic build"; exit 1; }
ABI="$WORK/a/abi/treasury.abi"
cmp -s "$ABI" "$WORK/b/abi/treasury.abi" || { echo "non-deterministic ABI"; exit 1; }
cmp -s "$ABI" "$SRC/abi/treasury.abi" || { echo "generated ABI differs from the reviewed copy"; exit 1; }

# 3. Entry point constants must equal sha256(name)[0:4] and the ABI.
node -e '
const fs = require("fs"), c = require("crypto");
const ep = n => parseInt(c.createHash("sha256").update(n).digest("hex").slice(0, 8), 16);
const src = fs.readFileSync(process.argv[1], "utf8"), index = fs.readFileSync(process.argv[2], "utf8"), abi = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
for (const [k, n] of [["TRANSFER_ENTRY_POINT", "transfer"], ["SET_POLICY_ENTRY_POINT", "set_policy"]]) {
  const m = src.match(new RegExp("const " + k + ": u32 = (0x[0-9a-f]{8})")); if (!m || parseInt(m[1], 16) !== ep(n)) { console.log("entry point constant " + k); process.exit(1); }
}
for (const n of ["authorize", "set_policy", "get_policy", "get_template"]) {
  if (!index.includes("case 0x" + ep(n).toString(16).padStart(8, "0") + ":")) { console.log("dispatcher lacks " + n); process.exit(1); }
  if (n !== "authorize" && abi.methods[n].entry_point !== ep(n)) { console.log("ABI entry point " + n); process.exit(1); }
}
if (Object.keys(abi.methods).sort().join() !== "get_policy,get_template,set_policy") { console.log("unexpected ABI methods"); process.exit(1); }
' "$SRC/assembly/Treasury.ts" "$SRC/assembly/index.ts" "$ABI"

# 4. Outputs + artifact manifest (hashes only; reproducible by anyone with the same inputs and toolchain).
cp "$WORK/a/build/release/contract.wasm" "$OUT/contract.wasm"; cp "$ABI" "$OUT/treasury.abi"
cp "$WORK/Deployment.ts" "$OUT/Deployment.ts"; cp "$WORK/inputs.canonical.json" "$OUT/inputs.json"
SOURCE=$(cd "$SRC" && find assembly scripts abi asconfig.json -type f ! -name Deployment.ts -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)
node -e '
const [out, wasm, abi, inputs, source, toolchain, tree] = process.argv.slice(1); const fs = require("fs"), c = require("crypto");
const sha = f => c.createHash("sha256").update(fs.readFileSync(f)).digest("hex");
const v = p => JSON.parse(fs.readFileSync(toolchain + "/" + p + "/package.json", "utf8")).version;
fs.writeFileSync(out + "/artifact.json", JSON.stringify({ schema: 1, template: "koinos-multisig-treasury", templateVersion: "1.0.0",
  inputsSha256: sha(inputs), sourceSha256: source, wasmSha256: sha(wasm), wasmSize: fs.statSync(wasm).size, abiSha256: sha(abi),
  toolchain: { tree: "koinos/koinos-contracts-as@4fc33bbe0520a77a89619da1e9e6efe98e7c423c contracts/koin (yarn --frozen-lockfile --ignore-scripts)", treeSha256: tree, sdkAs: v("@koinos/sdk-as"), assemblyscript: v("assemblyscript"), protoAs: v("@koinos/proto-as"), protoc: "3.21.12", node: process.version, arch: process.arch, flags: "--target release --use abort= --use BUILD_FOR_TESTING=0 --disable sign-extension" } }, null, 2) + "\n");
' "$OUT" "$OUT/contract.wasm" "$OUT/treasury.abi" "$OUT/inputs.json" "$SOURCE" "$TOOLCHAIN" "$TOOLCHAIN_TREE_SHA256"
echo "treasury artifact: $(stat -c %s "$OUT/contract.wasm") bytes sha256 $A (2 identical builds)"
