#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.."

# --- Find an OpenSSL 3.5+ binary (ML-KEM / ML-DSA / SLH-DSA need it) ---
is_35() {
  "$1" version 2>/dev/null | grep -Eq 'OpenSSL ([4-9]\.|3\.([5-9]|[1-9][0-9]))'
}

if [ -n "${OPENSSL_BIN:-}" ] && ! is_35 "$OPENSSL_BIN"; then
  echo "WARNING: OPENSSL_BIN=$OPENSSL_BIN is not OpenSSL 3.5+; searching for another." >&2
  unset OPENSSL_BIN
fi

if [ -z "${OPENSSL_BIN:-}" ]; then
  for c in "$(command -v openssl || true)" \
           /opt/homebrew/opt/openssl@3/bin/openssl \
           /usr/local/opt/openssl@3/bin/openssl \
           /opt/openssl35/bin/openssl \
           /nix/store/*-openssl-3.[5-9]*-bin/bin/openssl; do
    if [ -x "$c" ] && is_35 "$c"; then
      export OPENSSL_BIN="$c"
      break
    fi
  done
fi

if [ -n "${OPENSSL_BIN:-}" ]; then
  echo "Using $("$OPENSSL_BIN" version) at $OPENSSL_BIN"
else
  echo "WARNING: no OpenSSL 3.5+ found (system has: $(openssl version 2>/dev/null || echo none))." >&2
  echo "         PQC features will be degraded. Fix: use Docker (docker compose up --build)," >&2
  echo "         'brew install openssl@3' on macOS, or set OPENSSL_BIN to a 3.5+ binary. See NEXT_STEPS.md." >&2
fi

if [ ! -d "venv" ]; then
  python3 -m venv venv || python -m venv venv
fi

if [ -f "venv/bin/activate" ]; then
  source venv/bin/activate
elif [ -f "venv/Scripts/activate" ]; then
  source venv/Scripts/activate
fi

pip install -q -r requirements.txt
echo "Starting Quantum Guard on http://127.0.0.1:8000 ..."
uvicorn app.main:app --host 127.0.0.1 --port 8000
