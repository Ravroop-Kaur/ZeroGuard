#!/bin/sh
echo "[start] checking Rego"
opa check /srv/policies || echo "!!! REGO SYNTAX ERROR - all requests will be denied (fail closed)"
opa run --server --addr=127.0.0.1:8181 /srv/policies &
export OPA_URL=http://127.0.0.1:8181
ready=0
for i in $(seq 1 40); do
  if python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8181/health')" 2>/dev/null; then ready=1; break; fi
  sleep 0.5
done
[ "$ready" = 1 ] && echo "[start] OPA is up" || echo "!!! OPA did not start - requests will be denied (fail closed)"
exec python -m uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}"
