#!/usr/bin/env bash
# Starts Redis, the proxy (http://127.0.0.1:8000) and a public tunnel for Slack's button callbacks.
set -euo pipefail
cd "$(dirname "$0")/.."

[[ -f .env ]] || { echo "Missing .env (copy .env.example)"; exit 1; }
LOG_DIR=$(mktemp -d)
PIDS=()
cleanup() { kill "${PIDS[@]}" 2>/dev/null || true; rm -rf "$LOG_DIR"; }
trap cleanup EXIT INT TERM

if ! redis-cli -p 6379 ping >/dev/null 2>&1; then
  redis-server --port 6379 --bind 127.0.0.1 --save "" --appendonly no >"$LOG_DIR/redis.log" 2>&1 &
  PIDS+=($!)
fi

REDIS_URL=redis://127.0.0.1:6379/0 .venv-demo/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --log-level warning &
PIDS+=($!)

cloudflared tunnel --no-autoupdate --url http://127.0.0.1:8000 >"$LOG_DIR/tunnel.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 60); do
  URL=$(grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' "$LOG_DIR/tunnel.log" | head -1 || true)
  [[ -n "$URL" ]] && break
  sleep 0.5
done
[[ -n "${URL:-}" ]] || { echo "Tunnel did not start:"; cat "$LOG_DIR/tunnel.log"; exit 1; }

until curl -sf http://127.0.0.1:8000/health >/dev/null; do sleep 0.3; done
cat <<EOF

  Proxy:   http://127.0.0.1:8000  ($(curl -s http://127.0.0.1:8000/health))
  Public:  $URL

  Slack app > Interactivity & Shortcuts > Request URL (changes on every restart):
    $URL/api/v1/callbacks/slack

  Ctrl-C to stop.
EOF
wait
