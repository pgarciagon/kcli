#!/usr/bin/env bash
# Explicit, disposable Koinos-only multisig exercise namespace. Creates NEW containers/volumes/network only and
# refuses to reuse existing names; never restarts or removes anything that already exists.
# usage: multisig-local-setup.sh <lab chain config dir> <run id: kcli-msig-...> [lab tools volume]
set -euo pipefail
CONFIG=${1:?lab chain config dir (genesis_data.json + jsonrpc descriptors)}
RUN_ID=${2:?fresh lower-case run ID}
LAB_VOLUME=${3:-vortex-lab-work}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
[[ "$RUN_ID" =~ ^kcli-msig-[0-9a-z-]+[0-9a-f]{2}$ ]] || { echo 'run ID must be kcli-msig-...<2 hex>' >&2; exit 2; }
[[ "$(shasum -a 256 "$CONFIG/jsonrpc/descriptors/koinos_descriptors.pb" | cut -d' ' -f1)" == a30b35a0c781e13b0003722ea3ffa7e915d961aafc2ed37d51802a05cb07538a ]] || { echo 'unexpected descriptors' >&2; exit 2; }
# Digest-pinned images (same pins as the reviewed Vortex lab, resolved 2026-09-27).
NODE_IMG=node@sha256:0e910f435308c36ea60b4cfd7b80208044d77a074d16b768a81901ce938a62dc
ALPINE_IMG=alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
AMQP_IMG=rabbitmq@sha256:d7af1c87c5f1eda13fcfca06db452bf3aeab6619fc3358b68535c0c02c4e52bc
KOINOS_CHAIN_IMG=koinos/koinos-chain@sha256:52bff1523b91df86f32c393bd15241cb8b4cb78cd511bbbb7f0f49c509488b7d
KOINOS_MEMPOOL_IMG=koinos/koinos-mempool@sha256:40125193b3672ed2ca5e2a4e2460f783097b4fa995b431dd54d22070c2b80cef
KOINOS_BLOCKSTORE_IMG=koinos/koinos-block-store@sha256:9fe2bd6730d72c95fcb785f8b5b8d549a8fa87a299a89210bd9613c0278192e1
KOINOS_JSONRPC_IMG=koinos/koinos-jsonrpc@sha256:73a774bbbfd0b8db3254046db74adca4f859317bd342185cc324081c73c9c9da
KOINOS_TXSTORE_IMG=koinos/koinos-transaction-store@sha256:48e66c3bc3dbfd5a55de5b1e5cd643fcb0387128704c8ac551f5932d6a6e837c
NET=$RUN_ID-net; VOL=$RUN_ID-chain; WORK=$RUN_ID-exercise
if docker network inspect "$NET" >/dev/null 2>&1 || docker volume inspect "$VOL" >/dev/null 2>&1 || docker volume inspect "$WORK" >/dev/null 2>&1; then echo 'Namespace already exists; refuse reuse' >&2; exit 2; fi
for name in amqp mempool block-store chain tx-store jsonrpc controller; do
  if docker inspect "$RUN_ID-$name" >/dev/null 2>&1; then echo 'Container name exists; refuse reuse' >&2; exit 2; fi
done
L="label=kcli.multisig.exercise=$RUN_ID"
if [ -n "$(docker ps -aq --filter "$L")$(docker volume ls -q --filter "$L")$(docker network ls -q --filter "$L")" ]; then echo 'Resources with this run label already exist; refuse reuse' >&2; exit 2; fi
docker volume inspect "$LAB_VOLUME" >/dev/null
SUBNET="10.253.$((16#${RUN_ID: -2})).0/24"
docker network create --internal --subnet "$SUBNET" --label kcli.multisig.exercise="$RUN_ID" "$NET" >/dev/null
docker volume create --label kcli.multisig.exercise="$RUN_ID" "$VOL" >/dev/null
docker volume create --label kcli.multisig.exercise="$RUN_ID" "$WORK" >/dev/null
COPYFILE_DISABLE=1 tar -C "$CONFIG" -cf - . | docker run --rm -i --network none -v "$VOL:/chain-data" "$ALPINE_IMG" sh -ec 'tar -C /chain-data -xf - 2>/dev/null'
run() { local name=$1; shift; docker run -d --label kcli.multisig.exercise="$RUN_ID" --name "$RUN_ID-$name" --network "$NET" --network-alias "$name" "$@" >/dev/null; }
run amqp "$AMQP_IMG"
sleep 8
A=(-a amqp://guest:guest@amqp:5672/)
run mempool --platform linux/amd64 "$KOINOS_MEMPOOL_IMG" "${A[@]}"
run block-store --network-alias block_store --platform linux/amd64 -v "$VOL:/root/.koinos" "$KOINOS_BLOCKSTORE_IMG" "${A[@]}"
run chain --platform linux/amd64 -v "$VOL:/root/.koinos" "$KOINOS_CHAIN_IMG" "${A[@]}"
run tx-store --network-alias transaction_store --platform linux/amd64 -v "$VOL:/root/.koinos" "$KOINOS_TXSTORE_IMG" "${A[@]}"
run jsonrpc --platform linux/amd64 -v "$VOL:/root/.koinos" "$KOINOS_JSONRPC_IMG" "${A[@]}" -L /tcp/8080 -m 30
run controller --mount type=volume,source="$LAB_VOLUME",target=/lab,readonly -v "$WORK:/exercise" "$NODE_IMG" sleep infinity
docker cp "$ROOT/tests/multisig-local-chain.cjs" "$RUN_ID-controller:/exercise/controller.cjs"
echo "RUN_ID=$RUN_ID"
