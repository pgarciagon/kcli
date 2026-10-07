#!/usr/bin/env bash
# Explicit, disposable Koinos-only qualification. No existing containers/stores are restarted.
set -euo pipefail
SOURCE=${1:?clean pinned V2 checkout}
EXERCISE=${2:?existing private exercise directory}
RUN_ID=${3:?fresh lower-case run ID}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CTX=colima-vortex-v2-audit
D=(docker --context "$CTX")
[[ "$RUN_ID" =~ ^kcli-vortex-[0-9a-z-]+$ ]] || exit 2
[[ "$(git -C "$SOURCE" rev-parse HEAD)" == 42b0ab20653047ec0275c3130accf9210ce4b822 ]] || exit 2
[[ -z "$(git -C "$SOURCE" status --porcelain)" ]] || exit 2
[[ "$(shasum -a 256 "$SOURCE/lab/koinos/config/jsonrpc/descriptors/koinos_descriptors.pb" | cut -d' ' -f1)" == a30b35a0c781e13b0003722ea3ffa7e915d961aafc2ed37d51802a05cb07538a ]] || exit 2
source "$SOURCE/lab/images.lock"
META_IMG=koinos/koinos-contract-meta-store@sha256:3733ece76ce2f618afeecc5f2b9b6f5022cc9d0ebf43064bed0c6698e819b70a
NET=$RUN_ID-net; VOL=$RUN_ID-chain; WORK=$RUN_ID-exercise
if "${D[@]}" network inspect "$NET" >/dev/null 2>&1 || "${D[@]}" volume inspect "$VOL" >/dev/null 2>&1 || "${D[@]}" volume inspect "$WORK" >/dev/null 2>&1; then echo 'Namespace already exists; refuse reuse' >&2; exit 2; fi
for name in amqp mempool block-store chain tx-store meta-store jsonrpc controller producer; do
  if "${D[@]}" inspect "$RUN_ID-$name" >/dev/null 2>&1; then echo 'Container name exists; refuse reuse' >&2; exit 2; fi
done
# Explicit fresh subnet avoids exhausting Docker's default pools; collisions
# still refuse creation. No retained lab network/container/volume is removed.
SUBNET="10.254.$((16#${RUN_ID: -2})).0/24"
"${D[@]}" network create --internal --subnet "$SUBNET" --label kcli.vortex.exercise="$RUN_ID" "$NET" >/dev/null
"${D[@]}" volume create --label kcli.vortex.exercise="$RUN_ID" "$VOL" >/dev/null
"${D[@]}" volume create --label kcli.vortex.exercise="$RUN_ID" "$WORK" >/dev/null
COPYFILE_DISABLE=1 tar -C "$SOURCE/lab/koinos/config" -cf - . | "${D[@]}" run --rm -i --network none -v "$VOL:/chain-data" "$ALPINE_IMG" sh -ec 'tar -C /chain-data -xf -'
run() { local name=$1; shift; "${D[@]}" run -d --label kcli.vortex.exercise="$RUN_ID" --name "$RUN_ID-$name" --network "$NET" --network-alias "$name" "$@" >/dev/null; }
run amqp "$AMQP_IMG"
sleep 8
A=(-a amqp://guest:guest@amqp:5672/)
run mempool --platform linux/amd64 "$KOINOS_MEMPOOL_IMG" "${A[@]}"
run block-store --platform linux/amd64 -v "$VOL:/root/.koinos" "$KOINOS_BLOCKSTORE_IMG" "${A[@]}"
run chain --platform linux/amd64 -v "$VOL:/root/.koinos" "$KOINOS_CHAIN_IMG" "${A[@]}" --system-call-buffer-size 700000
run tx-store --network-alias transaction_store --platform linux/amd64 -v "$VOL:/root/.koinos" "$KOINOS_TXSTORE_IMG" "${A[@]}"
run meta-store --platform linux/amd64 -v "$VOL:/root/.koinos" "$META_IMG" "${A[@]}"
# An internal network deliberately has no published port. The harness uses a bounded
# native loopback relay through docker exec, without granting containers Internet access.
run jsonrpc --platform linux/amd64 -v "$VOL:/root/.koinos" "$KOINOS_JSONRPC_IMG" "${A[@]}" -L /tcp/8080 -m 30
run controller --mount type=volume,source=vortex-fresh-work-20261003,target=/work,readonly -v "$WORK:/exercise" "$NODE_IMG" sleep infinity
"${D[@]}" cp "$ROOT/tests/vortex-local-chain.cjs" "$RUN_ID-controller:/exercise/controller.cjs"
"${D[@]}" cp "$EXERCISE/input.json" "$RUN_ID-controller:/exercise/input.json"
"${D[@]}" exec "$RUN_ID-controller" node /exercise/controller.cjs bootstrap
"${D[@]}" cp "$RUN_ID-controller:/exercise/deployment.json" "$EXERCISE/deployment.json"
"${D[@]}" cp "$RUN_ID-controller:/exercise/bridge.abi" "$EXERCISE/bridge.abi"
echo "RUN_ID=$RUN_ID"
