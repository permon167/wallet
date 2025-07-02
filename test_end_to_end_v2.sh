#!/bin/bash

echo "🔐 1. Crear DID (simulado)"
curl -s -XPOST http://localhost:9000/2015-03-31/functions/function/invocations \
-H "Content-Type: application/json" \
-d '{
  "version": "2.0",
  "routeKey": "GET /create-did",
  "rawPath": "/create-did",
  "headers": { "Content-Type": "application/json" },
  "requestContext": { "http": { "method": "GET", "path": "/create-did", "sourceIp": "127.0.0.1" } },
  "isBase64Encoded": false
}' | tee tmp_did.json

HOLDER_DID=$(jq -r '.body' tmp_did.json | jq -r '.did')
echo "✅ DID creado: $HOLDER_DID"

echo "🎓 2. Emitir credencial (VC simulada)"
VC=$(curl -s -XPOST http://localhost:9000/2015-03-31/functions/function/invocations \
-H "Content-Type: application/json" \
-d "{
  \"version\": \"2.0\",
  \"routeKey\": \"POST /issue-credential\",
  \"rawPath\": \"/issue-credential\",
  \"headers\": { \"Content-Type\": \"application/json\" },
  \"requestContext\": { \"http\": { \"method\": \"POST\", \"path\": \"/issue-credential\", \"sourceIp\": \"127.0.0.1\" } },
  \"body\": \"{\\\"issuer_did\\\": \\\"did:key:issuer-123\\\", \\\"subject_did\\\": \\\"$HOLDER_DID\\\", \\\"course\\\": \\\"Python para TFM\\\", \\\"name\\\": \\\"Pablo Perez\\\"}\",
  \"isBase64Encoded\": false
}" | jq -r '.body')

echo "$VC" > tmp_vc.json
echo "✅ Credencial emitida y guardada en tmp_vc.json"

echo "💾 3. Almacenar VC en la wallet del holder"
ESCAPED_VC=$(cat tmp_vc.json | jq -c . | sed 's/"/\\\"/g')
curl -s -XPOST http://localhost:9000/2015-03-31/functions/function/invocations \
-H "Content-Type: application/json" \
-d "{
  \"version\": \"2.0\",
  \"routeKey\": \"POST /store-credential\",
  \"rawPath\": \"/store-credential\",
  \"headers\": { \"Content-Type\": \"application/json\" },
  \"requestContext\": { \"http\": { \"method\": \"POST\", \"path\": \"/store-credential\", \"sourceIp\": \"127.0.0.1\" } },
  \"body\": \"{\\\"did\\\": \\\"$HOLDER_DID\\\", \\\"vc\\\": $ESCAPED_VC}\",
  \"isBase64Encoded\": false
}" | tee tmp_store.json

echo "📤 4. Generar Verifiable Presentation (VP)"
VP=$(curl -s -XPOST http://localhost:9000/2015-03-31/functions/function/invocations \
-H "Content-Type: application/json" \
-d "{
  \"version\": \"2.0\",
  \"routeKey\": \"GET /present-credential/$HOLDER_DID\",
  \"rawPath\": \"/present-credential/$HOLDER_DID\",
  \"headers\": { \"Content-Type\": \"application/json\" },
  \"requestContext\": { \"http\": { \"method\": \"GET\", \"path\": \"/present-credential/$HOLDER_DID\", \"sourceIp\": \"127.0.0.1\" } },
  \"queryStringParameters\": { \"index\": \"0\" },
  \"isBase64Encoded\": false
}" | jq -r '.body')

echo "$VP" > tmp_vp.json
echo "✅ VP guardada en tmp_vp.json"

echo "🔎 5. Verificar presentación"
ESCAPED_VP=$(cat tmp_vp.json | jq -c . | sed 's/"/\\\"/g')
curl -s -XPOST http://localhost:9000/2015-03-31/functions/function/invocations \
-H "Content-Type: application/json" \
-d "{
  \"version\": \"2.0\",
  \"routeKey\": \"POST /verify-presentation\",
  \"rawPath\": \"/verify-presentation\",
  \"headers\": { \"Content-Type\": \"application/json\" },
  \"requestContext\": { \"http\": { \"method\": \"POST\", \"path\": \"/verify-presentation\", \"sourceIp\": \"127.0.0.1\" } },
  \"body\": \"$ESCAPED_VP\",
  \"isBase64Encoded\": false
}"
