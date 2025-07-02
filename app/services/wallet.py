import os
import json
import uuid
from datetime import datetime
from . import did_key
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

if os.environ.get("AWS_EXECUTION_ENV"):
    DATA_PATH = "/tmp/data"
else:
    DATA_PATH = "data"

def _get_wallet_path(did: str) -> str:
    os.makedirs(DATA_PATH, exist_ok=True)
    safe_did = did.replace(":", "_")
    return os.path.join(DATA_PATH, f"{safe_did}.enc")

def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def _encrypt_json(data: dict, password: str) -> dict:
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)

    plaintext = json.dumps(data).encode()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    return {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }

def _decrypt_json(enc_data: dict, password: str) -> dict:
    salt = base64.b64decode(enc_data["salt"])
    nonce = base64.b64decode(enc_data["nonce"])
    ciphertext = base64.b64decode(enc_data["ciphertext"])
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode())

def store_credential(did: str, credential: dict, password: str):
    path = _get_wallet_path(did)

    if os.path.exists(path):
        with open(path, "r") as f:
            enc_data = json.load(f)
        credentials = _decrypt_json(enc_data, password)
    else:
        credentials = []

    credentials.append(credential)
    enc_data = _encrypt_json(credentials, password)

    with open(path, "w") as f:
        json.dump(enc_data, f, indent=2)

    return {"message": "Credential stored", "total": len(credentials)}

def list_credentials(did: str, password: str):
    path = _get_wallet_path(did)

    if not os.path.exists(path):
        return {"credentials": []}

    with open(path, "r") as f:
        enc_data = json.load(f)

    try:
        credentials = _decrypt_json(enc_data, password)
    except Exception:
        return {"error": "Invalid password or corrupted file."}

    return {"credentials": credentials}

def present_credential(holder_did: str, password: str, index: int = 0):
    import json
    import os
    import uuid
    from datetime import datetime

    try:
        path = _get_wallet_path(holder_did)

        if not os.path.exists(path):
            return {"error": "No credentials found for this DID."}

        with open(path, "r") as f:
            enc_data = json.load(f)

        credentials = _decrypt_json(enc_data, password)

        if index >= len(credentials):
            return {"error": "Credential index out of range."}

        vc = credentials[index]

        holder_key_path = os.path.join("data", "holder_identity.json")
        if not os.path.exists(holder_key_path):
            return {"error": "Holder identity file not found."}

        with open(holder_key_path) as f:
            holder_identity = json.load(f)

        holder_privkey_b64 = holder_identity.get("privateKeyBase64")
        if not holder_privkey_b64:
            return {"error": "Holder private key not found in identity file."}

        vp = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": [vc],
            "holder": holder_did,
            "proof": {
                "type": "Ed25519Signature2020",
                "created": datetime.utcnow().isoformat() + "Z",
                "proofPurpose": "authentication",
                "verificationMethod": holder_did + "#key-1",
                "challenge": str(uuid.uuid4()),
                "domain": "example.org",
            }
        }

        vp_to_sign = vp.copy()
        vp_to_sign.pop("proof")

        from . import did_key

        jws = did_key.sign_json(vp_to_sign, holder_privkey_b64)
        vp["proof"]["jws"] = jws

        return vp

    except Exception as e:
        return {"error": f"Exception in present_credential: {str(e)}"}
