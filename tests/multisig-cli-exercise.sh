#!/usr/bin/env bash
# Opt-in installed-CLI qualification on a NEW disposable local chain (never part of `npm test`, never public).
# usage: multisig-cli-exercise.sh <lab chain config dir> <run id> <evidence dir> [builder] [kcli container] [lab tools volume]
# The kcli container has the locked dependencies and the candidate kcli linked as `kcli`; it joins the run's
# internal network only for this exercise and reaches the chain through a loopback relay. KEEP=1 keeps the
# namespace and workspaces for debugging; otherwise everything this run created is removed, also on failure.
set -euo pipefail
CONFIG=${1:?lab chain config dir}; RUN_ID=${2:?run id}; EVIDENCE=${3:?evidence dir}
BUILDER=${4:-msig-builder}; KCLI=${5:-msig-kcli}; LAB_VOLUME=${6:-vortex-lab-work}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
[[ "$RUN_ID" =~ ^kcli-msig-[0-9a-z-]+[0-9a-f]{2}$ ]] || { echo 'run ID must be kcli-msig-...<2 hex>' >&2; exit 2; }
C=$RUN_ID-controller; NET=$RUN_ID-net; PORT=18$((RANDOM % 900 + 100)); B=/work/$RUN_ID; K=/deps/e2e-$RUN_ID
[ ! -e "$EVIDENCE" ] && [ ! -e "$EVIDENCE.partial" ] || { echo 'evidence dir exists; refuse overwrite' >&2; exit 2; }
docker exec "$BUILDER" test ! -e "$B" || { echo 'builder workspace exists; refuse reuse' >&2; exit 2; }
docker exec "$KCLI" test ! -e "$K" || { echo 'kcli workspace exists; refuse reuse' >&2; exit 2; }
CREATED_B=0; CREATED_K=0
stop_pid() { # <container> <pid file>: stop exactly that process; forget the PID only once it is really gone
  docker exec "$1" sh -c "if [ -f $2 ]; then p=\$(cat $2); kill \$p 2>/dev/null; for i in \$(seq 50); do kill -0 \$p 2>/dev/null || break; sleep 0.1; done;
    if kill -0 \$p 2>/dev/null; then kill -9 \$p 2>/dev/null; sleep 0.5; fi; if kill -0 \$p 2>/dev/null; then echo 'process survived' >&2; exit 1; fi; rm -f $2; fi"
}
cleanup() {
  stop_pid "$KCLI" "$K/relay.pid" || true; stop_pid "$C" /exercise/producer.pid || true
  docker network disconnect "$NET" "$KCLI" 2>/dev/null || true
  if [ "${KEEP:-0}" != 1 ]; then
    [ "$CREATED_K" = 1 ] && docker exec "$KCLI" rm -r -- "$K" 2>/dev/null || true
    [ "$CREATED_B" = 1 ] && docker exec "$BUILDER" rm -r -- "$B" 2>/dev/null || true
    "$ROOT/tests/multisig-local-teardown.sh" "$RUN_ID" >/dev/null 2>&1 || true
  fi
}
# Refuse an existing namespace BEFORE arming cleanup, so cleanup only ever removes what this invocation set up.
L="label=kcli.multisig.exercise=$RUN_ID"
if docker network inspect "$NET" >/dev/null 2>&1 || docker inspect "$C" >/dev/null 2>&1 \
   || docker volume inspect "$RUN_ID-chain" >/dev/null 2>&1 || docker volume inspect "$RUN_ID-exercise" >/dev/null 2>&1 \
   || [ -n "$(docker ps -aq --filter "$L")$(docker volume ls -q --filter "$L")$(docker network ls -q --filter "$L")" ]; then
  echo 'namespace already exists; refuse reuse' >&2; exit 2
fi
trap cleanup EXIT
"$ROOT/tests/multisig-local-setup.sh" "$CONFIG" "$RUN_ID" "$LAB_VOLUME"
ctl() { docker exec "$C" node /exercise/controller.cjs "$@"; }
docker exec "$BUILDER" mkdir "$B"; CREATED_B=1; docker exec "$BUILDER" mkdir "$B/src" "$B/inputs" "$B/artifacts" "$B/names" "$B/gcm"
COPYFILE_DISABLE=1 tar -C "$ROOT/contracts/multisig-treasury" -cf - . | docker exec -i "$BUILDER" tar -C "$B/src" -xf - 2>/dev/null
COPYFILE_DISABLE=1 tar -C "$ROOT/tests/fixtures/lab-name-service" -cf - . | docker exec -i "$BUILDER" tar -C "$B/names" -xf - 2>/dev/null
asc() { docker exec "$BUILDER" bash -c "cd $1 && ln -s /lab/kca-4fc33bb/contracts/koin/node_modules node_modules && env -i PATH=/usr/local/bin:/usr/bin:/bin node node_modules/assemblyscript/bin/asc.js assembly/index.ts --target release --use abort= --use BUILD_FOR_TESTING=0 --disable sign-extension --config asconfig.json >/dev/null && mkdir -p $B/artifacts/$2 && cp build/release/contract.wasm $B/artifacts/$2/"; }
asc "$B/names" lab-names
docker exec "$BUILDER" cp -a /lab/kca-4fc33bb/contracts/get_contract_metadata/assembly /lab/kca-4fc33bb/contracts/get_contract_metadata/asconfig.json "$B/gcm/"
asc "$B/gcm" get-contract-metadata
ctl e2e-keys
docker exec "$C" tar -C /exercise/inputs -cf - . | docker exec -i "$BUILDER" tar -C "$B/inputs" -xf -
docker exec "$BUILDER" "$B/src/scripts/build.sh" "$B/src" "$B/inputs/e2e.json" "$B/artifacts/e2e"
docker exec "$C" mkdir -p /exercise/artifacts
docker exec "$BUILDER" tar -C "$B/artifacts" -cf - . | docker exec -i "$C" tar -C /exercise/artifacts -xf -
ctl e2e-chain
# kcli side: private work dir with the synthetic keys and the reproducible artifact.
docker exec "$KCLI" mkdir -m 700 "$K"; CREATED_K=1; docker exec "$KCLI" mkdir -m 700 "$K/artifact"
docker exec "$C" cat /exercise/e2e/keys.json | docker exec -i "$KCLI" sh -c "umask 077; cat > $K/keys.json"
docker exec "$BUILDER" tar -C "$B/artifacts/e2e" -cf - contract.wasm treasury.abi inputs.json artifact.json | docker exec -i "$KCLI" tar -C "$K/artifact" -xf -
WORKTREE=$(docker exec "$KCLI" sh -c 'dirname $(dirname $(readlink -f $(which kcli)))')
# Drivers are staged in the per-run workspace only; the installed candidate checkout is never modified.
docker exec "$KCLI" mkdir -m 700 "$K/driver"
docker cp "$ROOT/tests/multisig-relay.cjs" "$KCLI:$K/driver/multisig-relay.cjs"
docker cp "$ROOT/tests/multisig-local-e2e.js" "$KCLI:$K/driver/multisig-local-e2e.js"
docker network connect "$NET" "$KCLI"
# Exactly one block producer at a time: stopped (and confirmed gone) around controller actions that mine themselves.
producer_start() { docker exec -d "$C" sh -c 'node /exercise/controller.cjs producer & echo $! > /exercise/producer.pid; wait'; sleep 3; }
docker exec -d "$KCLI" node "$K/driver/multisig-relay.cjs" "$PORT" "$K/relay.pid"
producer_start
RPC=http://127.0.0.1:$PORT/
docker exec -e KCLI_ROOT="$WORKTREE" "$KCLI" node "$K/driver/multisig-local-e2e.js" deploy "$K" "$RPC"
stop_pid "$C" /exercise/producer.pid
docker exec "$KCLI" cat "$K/treasury.json" | docker exec -i "$C" sh -c 'cat > /exercise/e2e/treasury.json'
ctl e2e-verify
ctl e2e-bypass
ctl fund "$(docker exec "$C" node -e 'console.log(JSON.parse(require("fs").readFileSync("/exercise/e2e/keys.json")).treasury.address)')" 1000
producer_start
docker exec -e KCLI_ROOT="$WORKTREE" "$KCLI" node "$K/driver/multisig-local-e2e.js" operate "$K" "$RPC"
# Evidence is staged and only published as a whole.
mkdir -p "$EVIDENCE.partial"
docker exec "$KCLI" cat "$K/evidence-cli.json" > "$EVIDENCE.partial/evidence-cli.json"
docker exec "$C" cat /exercise/e2e/independent.json > "$EVIDENCE.partial/independent-bootstrap.json"
docker exec "$C" cat /exercise/e2e/bypass.json > "$EVIDENCE.partial/independent-bypass.json"
docker exec "$BUILDER" cat "$B/artifacts/e2e/artifact.json" > "$EVIDENCE.partial/artifact-e2e.json"
for f in treasury.json treasury-v1.json; do docker exec "$KCLI" cat "$K/$f" > "$EVIDENCE.partial/$f"; done
mv "$EVIDENCE.partial" "$EVIDENCE"
echo "EVIDENCE $EVIDENCE"
