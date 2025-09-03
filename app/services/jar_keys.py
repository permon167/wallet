import os
import pathlib
import json
from functools import lru_cache
from typing import Tuple, Dict, Any

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, BestAvailableEncryption
from cryptography.hazmat.backends import default_backend

import jwt  # PyJWT >= 2.x

KEY_PATH_ENV = "REQUEST_JWT_PRIVATE_KEY_PATH"
KEY_INLINE_ENV = "REQUEST_JWT_PRIVATE_KEY"
KEY_PASSWORD_ENV = "REQUEST_JWT_PRIVATE_KEY_PASS"  # opcional (PEM protegido)

DEFAULT_KEY_PATH = "./data/jar-ec256-key.pem"

def _ensure_dir(path: str):
    pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)

def _b64url(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _rfc7638_thumbprint(jwk: Dict[str, str]) -> str:
    # thumbprint de {"crv","kty","x","y"} orden lexicográfico, SHA-256, base64url
    ordered = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(json.dumps(ordered, separators=(",", ":"), sort_keys=True).encode())
    return _b64url(digest.finalize())

@lru_cache(maxsize=1)
def _load_private_key() -> ec.EllipticCurvePrivateKey:
    pem_inline = os.getenv(KEY_INLINE_ENV)
    if pem_inline:
        pem_inline = pem_inline.replace("\\n", "\n").encode()
        password = os.getenv(KEY_PASSWORD_ENV)
        password_bytes = password.encode() if password else None
        return serialization.load_pem_private_key(pem_inline, password=password_bytes, backend=default_backend())

    key_path = os.getenv(KEY_PATH_ENV, DEFAULT_KEY_PATH)
    if os.path.isfile(key_path):
        with open(key_path, "rb") as f:
            password = os.getenv(KEY_PASSWORD_ENV)
            password_bytes = password.encode() if password else None
            return serialization.load_pem_private_key(f.read(), password=password_bytes, backend=default_backend())

    # Genera una nueva clave si no existe
    _ensure_dir(key_path)
    private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    # Guardar sin passphrase (tests). Para prod, usa BestAvailableEncryption.
    pem = private_key.private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        NoEncryption()
    )
    with open(key_path, "wb") as f:
        f.write(pem)
    return private_key

@lru_cache(maxsize=1)
def _public_jwk_and_kid() -> Tuple[Dict[str, Any], str]:
    private_key = _load_private_key()
    public_key = private_key.public_key()
    numbers = public_key.public_numbers()

    x = numbers.x.to_bytes(32, "big")
    y = numbers.y.to_bytes(32, "big")
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(x),
        "y": _b64url(y),
        "alg": "ES256",
        "use": "sig",
    }
    kid = _rfc7638_thumbprint(jwk)
    jwk["kid"] = kid
    return jwk, kid

def jwks() -> Dict[str, Any]:
    jwk, _ = _public_jwk_and_kid()
    return {"keys": [jwk]}

def sign_request_object(payload: Dict[str, Any]) -> str:
    """
    Firma un Request Object (JAR) con ES256 + kid. Devuelve JWS compacto (str).
    """
    private_key = _load_private_key()
    _, kid = _public_jwk_and_kid()
    headers = {"alg": "ES256", "kid": kid, "typ": "JWT"}
    token = jwt.encode(payload, private_key, algorithm="ES256", headers=headers)
    # PyJWT 2.x devuelve str; si es bytes (1.x), decodifica:
    if isinstance(token, bytes):
        token = token.decode()
    return token
