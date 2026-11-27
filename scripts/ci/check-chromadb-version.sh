#!/usr/bin/env bash
# The ChromaDB server image must be the same version as the client in Suspicious/requirements.txt.
# Dependabot bumps the client; the image tag lives in four files nothing bumps. A skew (the dev stack ran a
# 1.5.5 server under a 1.5.9 client) is easy to miss, so CI compares them.
set -euo pipefail
cd "$(dirname "$0")/../.."

client=$(sed -n 's/^chromadb==\([0-9][^ #]*\).*/\1/p' Suspicious/requirements.txt)
[ -n "$client" ] || { echo "no chromadb== pin in Suspicious/requirements.txt" >&2; exit 2; }

fail=0
check() {  # file, extracted version
  if [ "$2" != "$client" ]; then
    echo "MISMATCH: $1 has ChromaDB server $2, the client pin is $client" >&2
    fail=1
  else
    echo "ok: $1 ($2)"
  fi
}
for f in CONFIG.md deployment/.env.example docs/getting-started/examples/deployment-env.example; do
  check "$f" "$(sed -n 's/^CHROMADB_VERSION=\([0-9][^ #]*\).*/\1/p' "$f" | head -1)"
done
check kubernetes/suspicious/values.yaml \
  "$(awk '/chroma/ {f=1} f && /tag:/ {gsub(/[" ]/,"",$2); print $2; exit}' kubernetes/suspicious/values.yaml)"
exit $fail
