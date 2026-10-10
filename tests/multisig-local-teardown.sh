#!/usr/bin/env bash
# Removes ONLY the exact resources created by multisig-local-setup.sh for this run ID, and only if each carries
# the label kcli.multisig.exercise=<run id>. Anything else is left untouched.
set -euo pipefail
RUN_ID=${1:?run id}
[[ "$RUN_ID" =~ ^kcli-msig-[0-9a-z-]+$ ]] || exit 2
labeled() { [ "$(docker "$1" inspect --format '{{ index .Labels "kcli.multisig.exercise" }}' "$2" 2>/dev/null)" = "$RUN_ID" ]; }
labeled_container() { [ "$(docker inspect --format '{{ index .Config.Labels "kcli.multisig.exercise" }}' "$1" 2>/dev/null)" = "$RUN_ID" ]; }
for name in controller jsonrpc tx-store chain block-store mempool amqp; do
  c="$RUN_ID-$name"; if docker inspect "$c" >/dev/null 2>&1; then labeled_container "$c" && docker rm -f "$c" >/dev/null || echo "skip unlabeled $c" >&2; fi
done
for v in "$RUN_ID-chain" "$RUN_ID-exercise"; do
  if docker volume inspect "$v" >/dev/null 2>&1; then labeled volume "$v" && docker volume rm "$v" >/dev/null || echo "skip unlabeled $v" >&2; fi
done
n="$RUN_ID-net"; if docker network inspect "$n" >/dev/null 2>&1; then labeled network "$n" && docker network rm "$n" >/dev/null || echo "skip unlabeled $n" >&2; fi
echo "removed $RUN_ID"
