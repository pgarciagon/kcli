#!/usr/bin/env bash
# Separately authorized official-testnet rehearsal (test-only keys and tKOIN; never Mainnet, never `npm test`).
# usage: multisig-testnet-rehearsal.sh <evidence dir> <funder key json> [builder] [kcli container] [lab tools volume]
# The kcli container joins Docker's default network only for this run (public testnet RPC) and leaves it after.
set -euo pipefail
EVIDENCE=${1:?evidence dir}; FUNDER=${2:?funder key json}; BUILDER=${3:-msig-builder}; KCLI=${4:-msig-kcli}
ROOT=$(cd "$(dirname "$0")/.." && pwd); RUN=testnet-$(date -u +%Y%m%d%H%M%S)
K=/deps/$RUN; B=/work/$RUN; RPC=https://testnet.koinosfoundation.org/jsonrpc
[ ! -e "$EVIDENCE" ] && [ ! -e "$EVIDENCE.partial" ] || { echo 'evidence dir exists; refuse overwrite' >&2; exit 2; }
docker exec "$KCLI" test ! -e "$K" && docker exec "$BUILDER" test ! -e "$B" || { echo 'workspace exists' >&2; exit 2; }
# The funder key is read ONCE through a no-follow descriptor that is validated (regular, 0600, one link, ours).
read_funder() {
  python3 -I -c 'import os,stat,sys
fd=os.open(sys.argv[1], os.O_RDONLY|os.O_NOFOLLOW); st=os.fstat(fd)
assert stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1 and st.st_uid==os.getuid(), "funder key must be a private regular file (0600, one link, yours)"
sys.stdout.buffer.write(os.read(fd, 65536))' "$FUNDER"
}
CREATED_K=0; CREATED_B=0; JOINED=0
cleanup() {
  [ "$CREATED_K" = 1 ] && docker exec "$KCLI" rm -f -- "$K/funder.json" 2>/dev/null || true
  [ "$JOINED" = 1 ] && docker network disconnect bridge "$KCLI" 2>/dev/null || true
  if [ "${KEEP:-0}" != 1 ]; then
    [ "$CREATED_K" = 1 ] && docker exec "$KCLI" rm -r -- "$K" 2>/dev/null || true
    [ "$CREATED_B" = 1 ] && docker exec "$BUILDER" rm -r -- "$B" 2>/dev/null || true
  fi
}
trap cleanup EXIT
WORKTREE=$(docker exec "$KCLI" sh -c 'dirname $(dirname $(readlink -f $(which kcli)))')
docker exec "$KCLI" mkdir -m 700 "$K"; CREATED_K=1; docker exec "$KCLI" mkdir -m 700 "$K/driver" "$K/artifact"
docker cp "$ROOT/tests/multisig-local-e2e.js" "$KCLI:$K/driver/multisig-local-e2e.js"
docker cp "$ROOT/tests/multisig-testnet-tools.cjs" "$KCLI:$K/driver/multisig-testnet-tools.cjs"
read_funder | docker exec -i "$KCLI" sh -c "umask 077; cat > $K/funder.json"
tool() { docker exec -e KCLI_ROOT="$WORKTREE" "$KCLI" node "$K/driver/multisig-testnet-tools.cjs" "$1" "$K" "${@:2}"; }
docker network connect bridge "$KCLI"; JOINED=1
tool precheck "$K/funder.json"
tool keys
# Reproducible testnet build of the personalized contract (only public inputs cross containers).
docker exec "$BUILDER" mkdir "$B"; CREATED_B=1; docker exec "$BUILDER" mkdir "$B/src"
COPYFILE_DISABLE=1 tar -C "$ROOT/contracts/multisig-treasury" -cf - . | docker exec -i "$BUILDER" tar -C "$B/src" -xf - 2>/dev/null
docker exec "$KCLI" cat "$K/inputs.json" | docker exec -i "$BUILDER" sh -c "cat > $B/inputs.json"
docker exec "$BUILDER" "$B/src/scripts/build.sh" "$B/src" "$B/inputs.json" "$B/out"
docker exec "$BUILDER" tar -C "$B/out" -cf - contract.wasm treasury.abi inputs.json artifact.json | docker exec -i "$KCLI" tar -C "$K/artifact" -xf -
# Upload Mana: measured with broadcast:false (nothing persisted), doubled; provisioning = limit + 1 tKOIN.
USED=$(tool estimate-upload "$K/funder.json" | sed -n 's/^UPLOAD_RC //p')
# Untrusted RPC output: digits only, bounded, before any arithmetic.
[[ "$USED" =~ ^[0-9]{1,12}$ ]] && [ "$USED" -gt 0 ] && [ "$USED" -le 1000000000 ] || { echo "implausible upload estimate" >&2; exit 2; }
DEPLOY_RC=$(( USED * 2 > 50000000 ? USED * 2 : 50000000 ))
PROVISION=$(( DEPLOY_RC / 100000000 + 1 ))
TREASURY=$(docker exec "$KCLI" node -e "console.log(JSON.parse(require('fs').readFileSync('$K/keys.json')).treasury.address)")
echo "upload rc used $USED -> limit $DEPLOY_RC, provisioning $PROVISION tKOIN to $TREASURY"
tool fund "$K/funder.json" "$TREASURY" "$PROVISION"
docker exec -e KCLI_ROOT="$WORKTREE" -e NETWORK=testnet -e DEPLOY_RC="$DEPLOY_RC" -e CALL_RC=20000000 "$KCLI" node "$K/driver/multisig-local-e2e.js" deploy "$K" "$RPC"
tool verify
tool bypass
tool fund "$K/funder.json" "$TREASURY" 5
docker exec -e KCLI_ROOT="$WORKTREE" -e NETWORK=testnet -e CALL_RC=20000000 "$KCLI" node "$K/driver/multisig-local-e2e.js" operate "$K" "$RPC"
mkdir -p "$EVIDENCE.partial"
for f in evidence-cli.json independent.json bypass.json treasury.json treasury-v1.json; do docker exec "$KCLI" cat "$K/$f" > "$EVIDENCE.partial/$f"; done
docker exec "$KCLI" cat "$K/artifact/artifact.json" > "$EVIDENCE.partial/artifact.json"
echo "{\"uploadRcUsed\": \"$USED\", \"deployRcLimit\": \"$DEPLOY_RC\", \"provisionedTkoin\": $PROVISION, \"treasury\": \"$TREASURY\"}" > "$EVIDENCE.partial/run.json"
mv "$EVIDENCE.partial" "$EVIDENCE"
echo "EVIDENCE $EVIDENCE"
