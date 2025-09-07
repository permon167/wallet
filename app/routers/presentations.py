# app/routers/presentations.py
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
import os, time, json, secrets, urllib.parse
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from jwt import encode as jwt_encode
import httpx  # <-- para envío asíncrono

from app.services import holder as holder_svc  # ← reutilizamos tu storage

router = APIRouter()
DATA_DIR = Path(os.getenv("DATA_DIR", "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

def cfg(k, d=""):
    return os.getenv(k, d).rstrip("/")

def base_url():
    return cfg("SERVER_BASE_URL")

def now() -> int:
    return int(time.time())

def b64u(b: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

# ===== Clave local del HOLDER para firmar la VP =====
HOLDER_KEY_PATH = DATA_DIR / "holder-es256.pem"

def load_or_create_holder_key():
    if HOLDER_KEY_PATH.exists():
        with open(HOLDER_KEY_PATH, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    pk = ec.generate_private_key(ec.SECP256R1())
    pem = pk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with open(HOLDER_KEY_PATH, "wb") as f:
        f.write(pem)
    return pk

def holder_did_from_key(priv) -> str:
    pub = priv.public_key().public_numbers()
    x = b64u(pub.x.to_bytes(32, "big"))
    y = b64u(pub.y.to_bytes(32, "big"))
    jwk = {"kty": "EC", "crv": "P-256", "x": x, "y": y}
    jwk_json = json.dumps(jwk, separators=(",", ":"), sort_keys=True).encode()
    return "did:jwk:" + b64u(jwk_json)

# ===== Cargar VCs desde tu wallet =====
def load_wallet_credentials(holder_did: str, password: str) -> list[str]:
    creds = holder_svc.load_credentials(holder_did, password)
    out = []
    for c in creds:
        if isinstance(c, str):
            out.append(c)
        elif isinstance(c, dict):
            if isinstance(c.get("credential"), str):
                out.append(c["credential"])
            elif isinstance(c.get("jwt"), str):
                out.append(c["jwt"])
    return out

# ===== Generar openid:// “estático” para VP =====
def build_openid_vp():
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    post_endpoint = cfg("RESPONSE_URI") or (base_url() + "/verifier/response")
    request_uri = (base_url()
                   + "/request?"
                   + urllib.parse.urlencode({
                        "client_id": base_url(),
                        "redirect_uri": post_endpoint,
                        "response_type": "vp_token",
                        "response_mode": "direct_post",
                        "scope": "openid",
                        "state": state,
                        "nonce": nonce,
                        "aud": "openid://",
                    }))
    openid_url = ("openid://?"
                  + urllib.parse.urlencode({
                        "client_id": base_url(),
                        "redirect_uri": post_endpoint,
                        "response_type": "vp_token",
                        "response_mode": "direct_post",
                        "scope": "openid",
                        "state": state,
                        "nonce": nonce,
                        "request_uri": request_uri,
                  }))
    return {
        "openid_url": openid_url,
        "state": state,
        "nonce": nonce,
        "redirect_uri": post_endpoint,
        "request_uri": request_uri,
    }

# ===== Construir VP-JWT mínima =====
def make_vp_jwt(vc_jwts: list[str], iss_did: str, aud: str, nonce: str, lifetime=180):
    iat = now()
    exp = iat + lifetime
    payload = {
        "iss": iss_did,
        "sub": iss_did,
        "aud": aud,
        "iat": iat,
        "exp": exp,
        "nonce": nonce,
        "vp": {
            "type": ["VerifiablePresentation"],
            "verifiableCredential": vc_jwts,
        },
    }
    priv = load_or_create_holder_key()
    headers = {"alg": "ES256", "typ": "JWT"}  # tu /verifier/response no exige kid
    jws = jwt_encode(payload, priv, algorithm="ES256", headers=headers)
    return jws, payload

def build_presentation_submission(count: int):
    desc = []
    for i in range(min(count, 3)):
        desc.append({
            "id": f"va{i+1}",
            "format": "jwt_vc",
            "path": f"$.vp.verifiableCredential[{i}]"
        })
    return {"id": "ps-1", "definition_id": "pd-auto", "descriptor_map": desc}

# ===== Endpoints =====

@router.post("/wallet/present")
async def wallet_present(request: Request):
    """
    Body:
    {
      "authorize_url": "<opcional>",
      "holder_did": "did:jwk:...",
      "password": "default",
      "select": [0,1,2],
      "send": true,      # si true, hace POST a /verifier/response
      "auth": {          # opcional: forzar destino y estado
        "redirect_uri": "https://<verifier>/verifier/response",
        "state": "CROSSVP_..."
      }
    }
    """
    body = await request.json()
    holder_did = body.get("holder_did")
    password = body.get("password", "default")
    select = body.get("select", [0])
    do_send = bool(body.get("send", False))

    # 1) Abrimos un “openid://” de VP local (sirve para QR/depuración)
    auth = build_openid_vp()

    # --- NEW: si el cliente mandó redirect_uri/state, respetarlos ---
    user_auth = (body.get("auth") or {})
    if isinstance(user_auth, dict):
        if user_auth.get("redirect_uri"):
            auth["redirect_uri"] = str(user_auth["redirect_uri"])
        if user_auth.get("state"):
            auth["state"] = str(user_auth["state"])

    # 2) Cargamos y seleccionamos VCs
    all_vcs = load_wallet_credentials(holder_did or "", password)
    chosen = []
    for idx in select:
        try:
            chosen.append(all_vcs[int(idx)])
        except Exception:
            pass
    if not chosen:
        return JSONResponse({"error": "No hay VCs para presentar"}, status_code=400)

    # 3) Firmamos la VP-JWT
    priv = load_or_create_holder_key()
    did_local = holder_did or holder_did_from_key(priv)
    vp_jwt, vp_payload = make_vp_jwt(
        vc_jwts=chosen, iss_did=did_local, aud="openid://", nonce=auth["nonce"]
    )
    pres_sub = build_presentation_submission(len(chosen))

    # 4) (Opcional) Enviar direct_post al verificador (ASÍNCRONO)
    sent = False
    post_status = None
    if do_send:
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.post(
                    auth["redirect_uri"],
                    data={
                        "state": auth["state"],
                        "vp_token": vp_jwt,
                        "presentation_submission": json.dumps(pres_sub),
                    },
                )
                sent = True
                post_status = resp.status_code
        except Exception as e:
            sent = False
            post_status = f"error: {e}"

    return JSONResponse({
        "ok": True,
        "openid_url": auth["openid_url"],  # útil para QR si send:false
        "state": auth["state"],
        "nonce": auth["nonce"],
        "vp_jwt": vp_jwt,
        "vp_payload": vp_payload,
        "presentation_submission": pres_sub,
        "sent": sent,
        "post_status": post_status
    })

