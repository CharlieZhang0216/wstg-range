#!/usr/bin/env bash
# Create a shared venv, install every machine's verify requirements, run probes.
#   ./tools/verify.sh machines/01-recon-config
#   ./tools/verify.sh --all
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENV="$ROOT/.venv"

if [ ! -x "$VENV/bin/python" ]; then
  python3 -m venv "$VENV"
fi
"$VENV/bin/python" -m pip install -q --upgrade pip >/dev/null 2>&1 || true

while IFS= read -r req; do
  echo "installing verify deps: $req"
  "$VENV/bin/python" -m pip install -q -r "$req"
done < <(find "$ROOT/machines" -path '*/verify/requirements.txt' | sort)

exec "$VENV/bin/python" "$ROOT/tools/runner.py" "$@"