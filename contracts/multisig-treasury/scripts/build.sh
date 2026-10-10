#!/bin/sh
# Reproducible build launcher. POSIX sh (no exported functions, no BASH_ENV) that ALWAYS replaces the whole
# environment before Bash starts: NODE_OPTIONS, NODE_PATH, LD_PRELOAD, BASH_FUNC_*, BASH_ENV and friends can
# never reach node/protoc. Invoke it directly (./build.sh or sh build.sh), never as `bash build.sh`.
# usage: build.sh <source dir> <deployment inputs json> <output dir>
set -eu
# Resolve our own directory with a fixed PATH and absolute tools only (nothing inherited is consulted).
PATH=/usr/local/bin:/usr/bin:/bin; export PATH; unset CDPATH
dir=$(/usr/bin/dirname -- "$0") || exit 1
here=$(cd -P -- "$dir" && /bin/pwd -P) || exit 1
[ -f "$here/build-inner.sh" ] && [ ! -L "$here/build-inner.sh" ] || { echo "build-inner.sh not found next to build.sh" >&2; exit 1; }
exec /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/nonexistent LANG=C.UTF-8 \
  ${TOOLCHAIN:+TOOLCHAIN="$TOOLCHAIN"} ${KOINOS_PROTO:+KOINOS_PROTO="$KOINOS_PROTO"} \
  /bin/bash --noprofile --norc -p "$here/build-inner.sh" "$@"
