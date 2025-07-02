from app.services import did_key
import json
import os

# Generar identidad del Holder
identity = did_key.generate_did_key()

# Mostrar por consola
print("✅ Holder DID:", identity["did"])
print("🔐 Clave privada (base64):", identity["privateKeyBase64"])
print("🔑 Clave pública (base58):", identity["publicKeyBase58"])

# Crear carpeta si no existe
os.makedirs("data", exist_ok=True)

# Guardar en archivo JSON
with open("data/holder_identity.json", "w") as f:
    json.dump(identity, f, indent=2)

print("\n💾 Guardado en: data/holder_identity.json")
