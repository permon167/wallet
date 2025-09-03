#!/usr/bin/env bash
set -euo pipefail

# --- Config rápida ---
BACKEND_PORT="${BACKEND_PORT:-8000}"
FRONTEND_URL="${FRONTEND_BASE_URL:-http://localhost:3000}"
NODE_PORT="${NODE_PORT:-8081}"
NGROK_REGION="${NGROK_REGION:-eu}"
EBSI_ENV="${EBSI_ENV:-pilot}"        # pilot | conformance
RELAX_VALIDATION="${RELAX_VALIDATION:-true}"

# --- Requisitos ---
need() { command -v "$1" >/dev/null 2>&1 || { echo "❌ Falta '$1' en PATH"; exit 1; }; }
need ngrok
need uvicorn
if ! command -v jq >/dev/null 2>&1; then
  echo "⚠️  No tengo 'jq'; usaré Python para parsear JSON."
  PARSE_JSON_WITH_PY=1
else
  PARSE_JSON_WITH_PY=0
fi

# --- Logs y limpieza ---
NGROK_LOG=".ngrok.log"
UVICORN_LOG=".uvicorn.log"
NODE_LOG=".verifier_node.log"
: > "$NGROK_LOG"; : > "$UVICORN_LOG"; : > "$NODE_LOG"

pids=()
cleanup() {
  echo -e "\n🧹 Deteniendo procesos..."
  for pid in "${pids[@]:-}"; do kill "$pid" >/dev/null 2>&1 || true; done
  echo "✅ Listo"
}
trap cleanup EXIT

# --- 1) ngrok ---
echo "🚇 Lanzando ngrok (region=$NGROK_REGION) → http://localhost:${BACKEND_PORT}"
ngrok http --region="$NGROK_REGION" "$BACKEND_PORT" --log=stdout --log-format=logfmt >"$NGROK_LOG" 2>&1 &
pids+=($!)
# Espera a que el inspector responda
echo -n "⏳ Esperando a que ngrok publique URL..."
for i in {1..30}; do
  if curl -sS http://127.0.0.1:4040/api/tunnels >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if ! curl -sS http://127.0.0.1:4040/api/tunnels >/dev/null 2>&1; then
  echo -e "\n❌ No pude contactar con el panel de ngrok (4040). Revisa $NGROK_LOG"; exit 1
fi
if [ "$PARSE_JSON_WITH_PY" -eq 0 ]; then
  NGROK_URL=$(curl -sS http://127.0.0.1:4040/api/tunnels | jq -r '.tunnels[]|select(.proto=="https")|.public_url' | head -n1)
else
  NGROK_URL=$(python3 - <<'PY'
import json,sys,urllib.request
data=json.load(urllib.request.urlopen('http://127.0.0.1:4040/api/tunnels'))
urls=[t['public_url'] for t in data.get('tunnels',[]) if t.get('proto')=='https']
print(urls[0] if urls else '')
PY
)
fi
if [ -z "${NGROK_URL:-}" ]; then
  echo "❌ No encontré URL pública en ngrok. Mira $NGROK_LOG"; exit 1
fi
echo -e "\n🌍 URL pública: $NGROK_URL"

# --- 2) Export env para FastAPI (antes de arrancar uvicorn) ---
export SERVER_BASE_URL="$NGROK_URL"
export FRONTEND_BASE_URL="$FRONTEND_URL"
export NODE_VERIFIER_URL="http://localhost:${NODE_PORT}/verify-vp"
export RELAX_VALIDATION="$RELAX_VALIDATION"

# --- 3) Arrancar verificador Node (EBSI) ---
if [ -d "verifier_node" ]; then
  echo "🟩 Arrancando verificador Node (puerto $NODE_PORT)…"
  (
    cd verifier_node
    if [ ! -d node_modules ]; then npm i; fi
    PORT="$NODE_PORT" EBSI_ENV="$EBSI_ENV" npm start >"../$NODE_LOG" 2>&1
  ) &
  pids+=($!)
else
  echo "⚠️  Carpeta verifier_node no encontrada. Omite verificador Node."
fi

# --- 4) Arrancar FastAPI (uvicorn) ---
echo "🐍 Arrancando FastAPI en :$BACKEND_PORT…"
uvicorn app.main:app --reload --port "$BACKEND_PORT" >"$UVICORN_LOG" 2>&1 &
pids+=($!)
sleep 1

# --- 5) Diagnóstico rápido ---
echo "🔎 Probar endpoints básicos:"
echo "  - Health:       $NGROK_URL/health"
echo "  - Swagger:      $NGROK_URL/docs"
echo "  - Callback GET: (esperado 405) $NGROK_URL/verifier/callback"
echo

# --- 6) Autorizar y mostrar OPENID4VP (para QR) ---
AUTH_JSON=$(curl -sS "$NGROK_URL/verifier/authorize")
if [ "$PARSE_JSON_WITH_PY" -eq 0 ]; then
  OPENID_URL=$(echo "$AUTH_JSON" | jq -r '.openid_url')
  STATE=$(echo "$AUTH_JSON" | jq -r '.state')
  NONCE=$(echo "$AUTH_JSON" | jq -r '.nonce')
else
  OPENID_URL=$(python3 - <<PY
import json,sys; d=json.loads(sys.stdin.read()); print(d.get("openid_url",""))
PY
<<<"$AUTH_JSON")
  STATE=$(python3 - <<PY
import json,sys; d=json.loads(sys.stdin.read()); print(d.get("state",""))
PY
<<<"$AUTH_JSON")
  NONCE=$(python3 - <<PY
import json,sys; d=json.loads(sys.stdin.read()); print(d.get("nonce",""))
PY
<<<"$AUTH_JSON")
fi

echo "🧾 Authorization Request:"
echo "  STATE = $STATE"
echo "  NONCE = $NONCE"
echo "  OPENID4VP URL (para QR) ="
echo "  $OPENID_URL"
echo

# --- 7) cURL útiles para probar ---
cat <<EOF
✅ cURL de prueba (conecta y guarda resultado; token falso → success=false):
curl -i -X POST "$NGROK_URL/verifier/callback" \\
  -H 'Content-Type: application/json' \\
  -d '{"state":"$STATE","vp_token":"eyJhbGciOiJQUkVURU5EQSIsInR5cCI6IkpXVCJ9.fake.fake"}'

📋 Ver último resultado guardado:
curl -sS "$NGROK_URL/verifier/last-result" | jq .

💡 Flujo real:
1) Abre tu frontend (npm start), pulsa "OIDC4VP" → verás el QR (usa el enlace de arriba).
2) En Lissi (móvil) → Scan → consiente.
3) Mira $NGROK_URL/verifier/last-result o /verification-result en tu PC.

Logs:
- ngrok:       $NGROK_LOG
- uvicorn:     $UVICORN_LOG
- verifierNode $NODE_LOG
(CTRL+C para parar todo)
EOF

# --- 8) Mantener vivo hasta CTRL+C ---
while true; do sleep 3600; done
