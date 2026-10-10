#!/usr/bin/env bash
# Opt-in contract qualification on a NEW disposable local chain (never part of `npm test`, never a public chain).
# usage: multisig-contract-exercise.sh <lab chain config dir> <run id> <evidence dir> [builder container] [lab tools volume]
# The builder is a pinned Node 22 container with protoc 3.21.12 and the lab tools volume mounted read-only at /lab.
set -euo pipefail
CONFIG=${1:?lab chain config dir}; RUN_ID=${2:?run id}; EVIDENCE=${3:?evidence dir}
BUILDER=${4:-msig-builder}; LAB_VOLUME=${5:-vortex-lab-work}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
C=$RUN_ID-controller
[ ! -e "$EVIDENCE" ] || { echo 'evidence dir exists; refuse overwrite' >&2; exit 2; }
"$ROOT/tests/multisig-local-setup.sh" "$CONFIG" "$RUN_ID" "$LAB_VOLUME"
ctl() { docker exec "$C" node /exercise/controller.cjs "$@"; }
ctl keys
# Builds: the reviewed source tree goes in by tar stream; only public inputs cross between containers.
B=/work/$RUN_ID
# A fresh builder workspace per run: never extract into an existing path.
docker exec "$BUILDER" test ! -e "$B" || { echo 'builder workspace exists; refuse reuse' >&2; exit 2; }
docker exec "$BUILDER" mkdir "$B"
docker exec "$BUILDER" mkdir "$B/src" "$B/inputs" "$B/artifacts"
COPYFILE_DISABLE=1 tar -C "$ROOT/contracts/multisig-treasury" -cf - . | docker exec -i "$BUILDER" tar -C "$B/src" -xf - 2>/dev/null
docker exec "$C" tar -C /exercise/inputs -cf - . | docker exec -i "$BUILDER" tar -C "$B/inputs" -xf -
for name in main allow seed seed-evil wrongchain; do
  docker exec "$BUILDER" "$B/src/scripts/build.sh" "$B/src" "$B/inputs/$name.json" "$B/artifacts/$name"
done
# LAB ONLY name-service stand-in (KOIN-backed Mana needs get_contract_address), built with the same toolchain.
docker exec "$BUILDER" mkdir -p "$B/names"
COPYFILE_DISABLE=1 tar -C "$ROOT/tests/fixtures/lab-name-service" -cf - . | docker exec -i "$BUILDER" tar -C "$B/names" -xf - 2>/dev/null
docker exec "$BUILDER" bash -c "cd $B/names && ln -s /lab/kca-4fc33bb/contracts/koin/node_modules node_modules && env -i PATH=/usr/local/bin:/usr/bin:/bin node node_modules/assemblyscript/bin/asc.js assembly/index.ts --target release --use abort= --use BUILD_FOR_TESTING=0 --disable sign-extension --config asconfig.json >/dev/null && mkdir -p $B/artifacts/lab-names && cp build/release/contract.wasm $B/artifacts/lab-names/"
# Official get_contract_metadata system contract (koinos-contracts-as@4fc33bb), which Mainnet routes call 112 to.
docker exec "$BUILDER" bash -c "mkdir -p $B/gcm && cp -a /lab/kca-4fc33bb/contracts/get_contract_metadata/assembly /lab/kca-4fc33bb/contracts/get_contract_metadata/asconfig.json $B/gcm/ && cd $B/gcm && ln -s /lab/kca-4fc33bb/contracts/koin/node_modules node_modules && env -i PATH=/usr/local/bin:/usr/bin:/bin node node_modules/assemblyscript/bin/asc.js assembly/index.ts --target release --use abort= --use BUILD_FOR_TESTING=0 --disable sign-extension --config asconfig.json >/dev/null && mkdir -p $B/artifacts/get-contract-metadata && cp build/release/contract.wasm $B/artifacts/get-contract-metadata/"
docker exec "$C" mkdir -p /exercise/artifacts
docker exec "$BUILDER" tar -C "$B/artifacts" -cf - . | docker exec -i "$C" tar -C /exercise/artifacts -xf -
ctl bootstrap
ctl matrix
mkdir -p "$EVIDENCE"
docker exec "$C" cat /exercise/evidence-contract.json > "$EVIDENCE/evidence-contract.json"
for name in main allow seed seed-evil wrongchain; do docker exec "$BUILDER" cat "$B/artifacts/$name/artifact.json" > "$EVIDENCE/artifact-$name.json"; done
echo "EVIDENCE $EVIDENCE"
