# app/routers/ebsi_bridge.py
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from urllib.parse import urlencode
import httpx, secrets, json, os, time, base64, jwt
from typing import Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

router = APIRouter(tags=["bridge"])

# ========= Helpers =========

def _tok(n: int) -> str:
    return secrets.token_urlsafe(n)

def b64url_to_int(b: str) -> int:
    pad = '=' * (-len(b) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(b + pad), "big")

def load_ec_private_key_from_pem(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_ec_private_key_from_jwk(jwk: dict):
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise RuntimeError("JWK debe ser EC P-256")
    d = b64url_to_int(jwk["d"])
    x = b64url_to_int(jwk["x"])
    y = b64url_to_int(jwk["y"])
    curve = ec.SECP256R1()
    pub_numbers = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=curve)
    priv_numbers = ec.EllipticCurvePrivateNumbers(private_value=d, public_numbers=pub_numbers)
    return priv_numbers.private_key()

def load_holder_private_key() -> ec.EllipticCurvePrivateKey:
    pem_path = os.getenv("HOLDER_PRIVATE_PEM_PATH", "data/holder_jwk_private.pem")
    jwk_json = os.getenv("HOLDER_PRIVATE_JWK_JSON")
    if jwk_json:
        return load_ec_private_key_from_jwk(json.loads(jwk_json))
    if os.path.exists(pem_path):
        return load_ec_private_key_from_pem(pem_path)
    raise RuntimeError("No se encontró clave privada del holder.")

# ========= Modelos =========

class PrepareResponse(BaseModel):
    state: str
    nonce: str

class IDProofIn(BaseModel):
    holder_did: str
    verifier_base: str
    state: str
    nonce: str
    aud: Optional[str] = "openid://"
    exp_secs: Optional[int] = 600
    kid: Optional[str] = None

# ========= Endpoints de prepare =========

@router.get("/bridge/prepare-vp", response_model=PrepareResponse, summary="Pre-flight verifier checks for VP flow (returns state/nonce)")
async def prepare_vp(verifier_base: str = Query(...), holder_did: str = Query(...)):
    state = _tok(12)
    nonce = _tok(9)

    client_metadata = {
        "authorization_endpoint": "openid://",
        "response_types_supported": ["vp_token", "id_token"],
        "vp_formats_supported": {
            "jwt_vc": {"alg_values_supported": ["ES256"]},
            "jwt_vc_json": {"alg_values_supported": ["ES256"]},
            "jwt_vp": {"alg_values_supported": ["ES256"]},
            "jwt_vp_json": {"alg_values_supported": ["ES256"]},
        },
    }

    wk = f"{verifier_base}/.well-known/openid-configuration"
    auth_qs = {
        "client_id": holder_did,
        "client_metadata": json.dumps(client_metadata),
        "nonce": nonce,
        "redirect_uri": "openid://",
        "response_type": "code",
        "scope": "openid ver_test:vp_token",
        "state": state,
    }
    auth = f"{verifier_base}/authorize?{urlencode(auth_qs)}"
    req_qs = {
        "client_id": holder_did,
        "redirect_uri": f"{verifier_base}/verifier/response",
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "scope": "openid",
        "state": state,
        "nonce": nonce,
        "aud": "openid://",
    }
    req = f"{verifier_base}/request?{urlencode(req_qs)}"

    timeout = httpx.Timeout(15.0, connect=15.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as c:
        if (await c.get(wk)).status_code != 200:
            raise HTTPException(502, ".well-known failed")
        r2 = await c.get(auth)
        if r2.status_code not in (200, 302):
            raise HTTPException(502, "/authorize failed")
        if (await c.get(req)).status_code != 200:
            raise HTTPException(502, "/request failed")

    return {"state": state, "nonce": nonce}

@router.get("/bridge/prepare-id", response_model=PrepareResponse, summary="Pre-flight verifier checks for ID flow (returns state/nonce)")
async def prepare_id(verifier_base: str = Query(...), holder_did: str = Query(...)):
    state = _tok(12)
    nonce = _tok(9)

    client_metadata = {
        "authorization_endpoint": "openid://",
        "response_types_supported": ["vp_token", "id_token"],
        "vp_formats_supported": {
            "jwt_vc": {"alg_values_supported": ["ES256"]},
            "jwt_vc_json": {"alg_values_supported": ["ES256"]},
            "jwt_vp": {"alg_values_supported": ["ES256"]},
            "jwt_vp_json": {"alg_values_supported": ["ES256"]},
        },
    }

    wk = f"{verifier_base}/.well-known/openid-configuration"
    auth_qs = {
        "client_id": holder_did,
        "client_metadata": json.dumps(client_metadata),
        "nonce": nonce,
        "redirect_uri": "openid://",
        "response_type": "code",
        "scope": "openid ver_test:id_token",
        "state": state,
    }
    auth = f"{verifier_base}/authorize?{urlencode(auth_qs)}"
    req_qs = {
        "client_id": holder_did,
        "redirect_uri": f"{verifier_base}/verifier/response",
        "response_type": "id_token",
        "response_mode": "direct_post",
        "scope": "openid",
        "state": state,
        "nonce": nonce,
        "aud": "openid://",
    }
    req = f"{verifier_base}/request?{urlencode(req_qs)}"

    timeout = httpx.Timeout(15.0, connect=15.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as c:
        if (await c.get(wk)).status_code != 200:
            raise HTTPException(502, ".well-known failed")
        r2 = await c.get(auth)
        if r2.status_code not in (200, 302):
            raise HTTPException(502, "/authorize failed")
        if (await c.get(req)).status_code != 200:
            raise HTTPException(502, "/request failed")

    return {"state": state, "nonce": nonce}

# ========= Endpoint de id-proof =========

@router.post("/holder/id-proof", summary="Create and send a simple ES256 id_token to the verifier via direct_post")
async def id_proof(body: IDProofIn):
    try:
        private_key = load_holder_private_key()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Clave privada: {e}")

    now = int(time.time())
    claims = {
        "iss": body.holder_did,
        "sub": body.holder_did,
        "aud": body.aud or "openid://",
        "iat": now,
        "exp": now + int(body.exp_secs or 600),
        "nonce": body.nonce,
        "state": body.state,
    }
    headers = {"alg": "ES256", "typ": "JWT"}
    if body.kid:
        headers["kid"] = body.kid

    try:
        id_token = jwt.encode(claims, private_key, algorithm="ES256", headers=headers)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"No se pudo firmar id_token: {e}")

    url = f"{body.verifier_base}/verifier/response"
    form = {"state": body.state, "id_token": id_token}

    async with httpx.AsyncClient(timeout=15.0) as c:
        r = await c.post(url, data=form)
        if r.status_code not in (200, 302):
            raise HTTPException(502, f"verifier/response {r.status_code}: {r.text}")

    return {"ok": True, "state": body.state}
