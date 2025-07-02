#!/bin/bash

# Datos Holder e Issuer reales
HOLDER_DID="did:key:z6MkuAzFg9DToPdjd9HCNCro2KRwEz7FuqWMN8ubkCJSA3RT"
ISSUER_DID="did:key:z6Mknn1SKs6RKGByuUEJfXKRuEXrQRq8axhwScmyTWRVQQpQ"
PASSWORD="clave123"

echo "1️⃣ Proponer credencial al issuer"
curl -s -X POST http://localhost:8000/issue/propose \
-H "Content-Type: application/json" \
-d "{
  \"holder_did\": \"$HOLDER_DID\",
  \"credential_preview\": [
    { \"name\": \"grado\", \"value\": \"Universitario\" },
    { \"name\": \"dni\", \"value\": \"12345678X\" }
  ]
}" | jq .

echo -e "\n\n2️⃣ Solicitar emisión de credencial"
curl -s -X POST http://localhost:8000/issue/request \
-H "Content-Type: application/json" \
-d "{
  \"holder_did\": \"$HOLDER_DID\",
  \"password\": \"$PASSWORD\",
  \"attributes\": [
    { \"name\": \"grado\", \"value\": \"Universitario\" },
    { \"name\": \"dni\", \"value\": \"12345678X\" }
  ]
}" | jq .

echo -e "\n\n3️⃣ Listar credenciales guardadas en wallet"
curl -s -X POST http://localhost:8000/wallet/list \
-H "Content-Type: application/json" \
-d "{
  \"did\": \"$HOLDER_DID\",
  \"password\": \"$PASSWORD\"
}" | jq .

echo -e "\n\n4️⃣ Crear presentación de la primera credencial"
response=$(curl -s -X POST http://localhost:8000/present \
  -H "Content-Type: application/json" \
  -d "{
    \"holder_did\": \"$HOLDER_DID\",
    \"password\": \"$PASSWORD\",
    \"index\": 0
  }")

echo "$response" | jq . > vp.json
echo "$response" | jq .




echo -e "\n\n5️⃣ Verificar presentación con el verificador"
curl -s -X POST http://localhost:8000/verify-credential \
  -H "Content-Type: application/json" \
  --data-binary @vp.json | jq .
