
from app.services import did_key
import json
import os

# Generar nueva identidad del emisor
identity = did_key.generate_did_key()

# Mostrar por pantalla
print("✅ DID:", identity["did"])
print("🔐 Private key (base64):", identity["privateKeyBase64"])
print("🔑 Public key (base58):", identity["publicKeyBase58"])

# Crear carpeta si no existe
os.makedirs("data", exist_ok=True)

# Guardar en archivo JSON
with open("data/issuer_identity.json", "w") as f:
    json.dump(identity, f, indent=2)

print("\n💾 Guardado en: data/issuer_identity.json")
