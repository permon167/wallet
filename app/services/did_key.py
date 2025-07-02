from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import RawEncoder
from nacl.exceptions import BadSignatureError
import base58
import base64
import json

# ✅ 1. Generar par de claves y DID real (did:key)
def generate_did_key():
    sk = SigningKey.generate()
    vk = sk.verify_key

    # Multicodec Ed25519 public key (0xed01) + base58
    multicodec_prefix = b'\xed\x01'
    did_key = "did:key:z" + base58.b58encode(multicodec_prefix + vk.encode()).decode()

    return {
        "did": did_key,
        "privateKeyBase64": base64.b64encode(sk.encode()).decode(),
        "publicKeyBase58": base58.b58encode(vk.encode()).decode()
    }

# ✅ 2. Firmar un JSON con clave privada base64 (Ed25519)
def sign_json(data: dict, private_key_b64: str) -> str:
    sk = SigningKey(base64.b64decode(private_key_b64))
    message = json.dumps(data, separators=(",", ":"), sort_keys=True).encode()
    signature = sk.sign(message).signature
    return base64.b64encode(signature).decode()

# ✅ 3. Verificar firma con clave pública base58
def verify_json(data: dict, signature_b64: str, public_key_b58: str) -> bool:
    vk = VerifyKey(base58.b58decode(public_key_b58), encoder=RawEncoder)
    message = json.dumps(data, separators=(",", ":"), sort_keys=True).encode()
    try:
        vk.verify(message, base64.b64decode(signature_b64))
        return True
    except BadSignatureError:
        return False

# ✅ Ejemplo de uso (puedes comentar esto al integrarlo)
if __name__ == "__main__":
    identity = generate_did_key()
    print("DID:", identity["did"])

    cred = {"name": "Sara", "grado": "Universitario"}
    sig = sign_json(cred, identity["privateKeyBase64"])
    print("Signature (base64):", sig)

    valid = verify_json(cred, sig, identity["publicKeyBase58"])
    print("Signature valid:", valid)
