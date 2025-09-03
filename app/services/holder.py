import os
import json
import base64
import time
import uuid
from datetime import datetime

import jwt  # PyJWT
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key


# === Utilidades de cifrado local ===========================================

def _path(holder_did: str) -> str:
    return f"data/{holder_did.replace(':', '_')}_wallet.json"

def _encrypt(data: str, password: str) -> dict:
    salt = os.urandom(16)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000).derive(password.encode())
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    encrypted = aesgcm.encrypt(nonce, data.encode(), None)
    return {
        "ciphertext": base64.b64encode(encrypted).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "salt": base64.b64encode(salt).decode()
    }

def _decrypt(enc: dict, password: str) -> str:
    ciphertext = base64.b64decode(enc["ciphertext"])
    nonce = base64.b64decode(enc["nonce"])
    salt = base64.b64decode(enc["salt"])
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000).derive(password.encode())
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()


# === Creación de identidad did:jwk ========================================

def create_did_jwk() -> dict:
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    public_numbers = public_key.public_numbers()
    x = base64.urlsafe_b64encode(public_numbers.x.to_bytes(32, "big")).rstrip(b"=").decode()
    y = base64.urlsafe_b64encode(public_numbers.y.to_bytes(32, "big")).rstrip(b"=").decode()

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y
    }

    jwk_str = json.dumps(jwk, separators=(",", ":"))
    did = "did:jwk:" + base64.urlsafe_b64encode(jwk_str.encode()).decode().rstrip("=")

    os.makedirs("data", exist_ok=True)

    with open("data/holder_jwk_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("data/holder_jwk_identity.json", "w") as f:
        json.dump({
            "did": did,
            "jwk": jwk
        }, f, indent=2)

    return {"did": did, "jwk": jwk}


# === Proof of Possession para OpenID4VCI (ES256) ===========================

def build_proof_of_possession_jwk(nonce: str, issuer: str) -> dict:
    with open("data/holder_jwk_private.pem", "rb") as key_file:
        private_key = load_pem_private_key(key_file.read(), password=None)

    with open("data/holder_jwk_identity.json", "r") as f:
        identity = json.load(f)

    holder_did = identity["did"]
    now = int(time.time())
    payload = {
        "iss": holder_did,
        "sub": holder_did,
        "aud": issuer,
        "iat": now,
        "exp": now + 600,
        "nonce": nonce
    }

    token = jwt.encode(
	payload,
    	private_key,
    	algorithm="ES256",
    	headers={
        	"kid": holder_did,
        	"typ": "openid4vci-proof+jwt"
    	}
    )

    return {"jwt": token}


# === Almacenamiento de credenciales encriptadas ============================

def store_credential(holder_did: str, credential: dict, password: str) -> dict:
    path = _path(holder_did)
    os.makedirs("data", exist_ok=True)
    creds = []

    if os.path.exists(path):
        with open(path, "r") as f:
            enc = json.load(f)
        try:
            decrypted = _decrypt(enc, password)
            creds = json.loads(decrypted)
        except Exception:
            raise Exception("No se pudo desencriptar la wallet. ¿Contraseña incorrecta?")

    creds.append(credential)
    encrypted = _encrypt(json.dumps(creds), password)

    with open(path, "w") as f:
        json.dump(encrypted, f, indent=2)

    return {"status": "stored", "total": len(creds)}


def load_credentials(holder_did: str, password: str) -> list:
    path = _path(holder_did)
    if not os.path.exists(path):
        raise FileNotFoundError("Wallet no encontrada")

    with open(path, "r") as f:
        enc = json.load(f)
    decrypted = _decrypt(enc, password)
    return json.loads(decrypted)


def generate_presentation_jwt(holder_did: str, password: str, index: int = 0, aud: str = "", nonce: str = "") -> str:
    creds = load_credentials(holder_did, password)
    if index >= len(creds):
        raise ValueError("Índice de credencial inválido")
    
    vc_jwt = creds[index]  # Asumimos que ya está en formato JWT

    with open("data/holder_jwk_private.pem", "rb") as key_file:
        private_key = load_pem_private_key(key_file.read(), password=None)

    now = int(time.time())
    payload = {
        "iss": holder_did,
        "sub": holder_did,
        "vp": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": [vc_jwt]
        },
        "aud": aud or "https://verifier.example.org",  # temporal
        "nonce": nonce or str(uuid.uuid4()),
        "iat": now,
        "exp": now + 600
    }

    headers = {
        "alg": "ES256",
        "kid": holder_did,
        "typ": "JWT"
    }

    return jwt.encode(payload, private_key, algorithm="ES256", headers=headers)



def decode_jwt_credential(holder_did: str, password: str, index: int = 0) -> dict:
    creds = load_credentials(holder_did, password)
    if index < 0 or index >= len(creds):
        raise ValueError("Índice inválido")
    
    vc_jwt = creds[index]["credential"] if isinstance(creds[index], dict) and "credential" in creds[index] else creds[index]
    
    decoded = jwt.decode(vc_jwt, options={"verify_signature": False})
    
    return {
        "issuer": decoded.get("iss") or decoded.get("vc", {}).get("issuer"),
        "subject": decoded.get("sub") or decoded.get("vc", {}).get("credentialSubject", {}).get("id"),
        "types": decoded.get("vc", {}).get("type"),
        "expiration": decoded.get("exp"),
        "raw": decoded
    }
