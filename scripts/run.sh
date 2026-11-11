#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.."

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
