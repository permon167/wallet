# app/routers/verifier_ebsi.py
from __future__ import annotations

import os
import json
import time
import secrets
import urllib.parse
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response, PlainTextResponse

# Firmado JAR + JWKS
from app.services.jar_keys import sign_request_object, jwks as jwks_fn

try:
    # PyJWT
    from jwt import decode as jwt_decode
except Exception:  # pragma: no cover
    jwt_decode = None  # sólo para evitar crash si no está instalado

router = APIRouter()

# -----------------------------
# Helpers de configuración/base
# -----------------------------
def cfg(key: str, default: str = "") -> str:
    return os.getenv(key, default).rstrip("/")

def _base_url_from_request(req: Optional[Request]) -> str:
    if req:
        return str(req.base_url).rstrip("/")
    return "http://localhost:8000"

def base_url(req: Optional[Request] = None) -> str:
    return cfg("SERVER_BASE_URL") or _base_url_from_request(req)

def gen_id(n: int = 16) -> str:
    return secrets.token_urlsafe(n)

def now_ts() -> int:
    return int(time.time())

# -----------------------------
# Estado en memoria
# -----------------------------
STATE_STORE: Dict[str, Dict[str, Any]] = {}
LAST_RESULT: Dict[str, Any] = {}

# -----------------------------
# Well-known OIDC + JWKS + token stub
# -----------------------------
@router.get("/.well-known/openid-configuration")
async def well_known(request: Request):
    base = base_url(request)
    return JSONResponse({
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "jwks_uri": f"{base}/jwks.json",
        "scopes_supported": ["openid"],
        "response_types_supported": ["code", "id_token", "vp_token"],
        "response_modes_supported": ["fragment", "query", "form_post", "direct_post"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256", "ES256"],
        "grant_types_supported": ["authorization_code", "implicit"],
        "request_object_signing_alg_values_supported": ["ES256"],
        "request_uri_parameter_supported": True
    })

@router.get("/jwks.json")
async def jwks():
    return JSONResponse(jwks_fn())

@router.post("/token")
async def token_stub():
    # No emitimos tokens reales; sólo para conformidad del metadata
    return JSONResponse(
        {
            "error": "unsupported_grant_type",
            "error_description": "This AS is only for EBSI verifier conformance redirection tests."
        },
        status_code=400
    )

# -----------------------------
# Utilidades de parseo
# -----------------------------
def _build_openid_request(params: Dict[str, Any]) -> str:
    return "openid://?" + urllib.parse.urlencode(params)

def _build_request_uri(req: Request, path: str, params: Dict[str, Any]) -> str:
    return f"{base_url(req)}{path}?" + urllib.parse.urlencode(params)

def _parse_wallet_aud_hint(q: Dict[str, str]) -> str:
    """
    EBSI manda client_metadata con {"authorization_endpoint":"openid://"}.
    Si existe, lo usamos como 'aud'. En su defecto, si client_id es did:*, usamos eso.
    Si no, devolvemos "openid://".
    """
    cm_raw = q.get("client_metadata")
    if cm_raw:
        try:
            ae = json.loads(cm_raw).get("authorization_endpoint")
            if ae:
                return ae
        except Exception:
            pass
    cid = q.get("client_id") or ""
    return "openid://" if not cid.startswith("did:") else cid

# -----------------------------
# Authorization Endpoint (usado por EBSI) - ¡NO TOCAR!
# -----------------------------
@router.get("/authorize")
async def authorize(request: Request):
    """
    Compatibilidad EBSI:
      - EBSI llama con response_type=code y scope=openid ver_test:id_token|vp_token
      - Aquí detectamos el flujo (ID/VP) y respondemos con 302 a openid://?request_uri=...
    """
    q = dict(request.query_params)
    b = base_url(request)

    client_id_in = q.get("client_id") or cfg("CLIENT_ID") or b
    post_endpoint = cfg("RESPONSE_URI") or (b + "/verifier/response")
    original_redirect = q.get("redirect_uri") or cfg("REDIRECT_URI") or "openid://"
    state = q.get("state") or gen_id()
    nonce = q.get("nonce") or gen_id()
    wallet_aud = _parse_wallet_aud_hint(q)

    # Detección de flujo según parámetros EBSI
    scope_in = (q.get("scope") or "").strip()
    requested_rt = (q.get("response_type") or "").strip()
    flow_hint = (q.get("flow") or "").strip()
    is_id = ("ver_test:id_token" in scope_in) or (requested_rt == "id_token") or (flow_hint == "id")
    is_vp = ("ver_test:vp_token" in scope_in) or (requested_rt == "vp_token") or (flow_hint == "vp")
    if not (is_id or is_vp):
        is_id = True

    if is_id:
        req_obj = {
            "client_id": client_id_in,
            "redirect_uri": post_endpoint,
            "response_type": "id_token",
            "response_mode": "direct_post",
            "scope": "openid",
            "state": state,
            "nonce": nonce
        }
        flow_label = "id_token"
    else:
        req_obj = {
            "client_id": client_id_in,
            "redirect_uri": post_endpoint,
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "scope": "openid",
            "state": state,
            "nonce": nonce
        }
        flow_label = "vp_token"

    # Guardamos el redirect original para el 302 final post direct_post
    STATE_STORE[state] = {
        "redirect_uri_original": original_redirect,
        "flow": flow_label
    }

    # Construimos request_uri absoluto
    request_uri = _build_request_uri(request, "/request", {**req_obj, "aud": wallet_aud})
    openid_url = _build_openid_request({**req_obj, "request_uri": request_uri})

    # Redirección clásica (para wallets móviles o el conformance wallet)
    return RedirectResponse(url=openid_url, status_code=302)

# -----------------------------
# NUEVO: endpoint JSON sólo para el frontend (no usado por EBSI)
# -----------------------------
@router.get("/authorize/openid")
async def authorize_openid(request: Request):
    """
    Genera la misma Authorization Request que /authorize, pero devuelve JSON:
      { "openid_url": "openid://?...request_uri=..." }
    Útil para mostrar QR en desktop sin navegar a openid://
    """
    q = dict(request.query_params)
    b = base_url(request)

    client_id_in = q.get("client_id") or cfg("CLIENT_ID") or b
    post_endpoint = cfg("RESPONSE_URI") or (b + "/verifier/response")
    original_redirect = cfg("REDIRECT_URI") or "openid://"
    state = q.get("state") or gen_id()
    nonce = q.get("nonce") or gen_id()
    wallet_aud = _parse_wallet_aud_hint(q)

    flow = (q.get("flow") or "").strip() or "vp"
    if flow == "id":
        req_obj = {
            "client_id": client_id_in,
            "redirect_uri": post_endpoint,
            "response_type": "id_token",
            "response_mode": "direct_post",
            "scope": "openid",
            "state": state,
            "nonce": nonce
        }
        flow_label = "id_token"
    else:
        req_obj = {
            "client_id": client_id_in,
            "redirect_uri": post_endpoint,
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "scope": "openid",
            "state": state,
            "nonce": nonce
        }
        flow_label = "vp_token"

    # Guardamos estado para que /verifier/response acepte el direct_post
    STATE_STORE[state] = {
        "redirect_uri_original": original_redirect,
        "flow": flow_label
    }

    request_uri = _build_request_uri(request, "/request", {**req_obj, "aud": wallet_aud})
    openid_url = _build_openid_request({**req_obj, "request_uri": request_uri})
    return JSONResponse({"openid_url": openid_url})

# -----------------------------
# Request Object (JAR firmado)
# -----------------------------
@router.get("/request")
async def get_request_object(request: Request):
    """
    Devuelve el JAR (JWS compacto) con JOSE header estricto:
      {"alg":"ES256","kid":"...","typ":"JWT"}
    - Para id_token: parámetros OIDC básicos.
    - Para vp_token: incluye presentation_definition (3 input_descriptors) + vp_formats.
    """
    q = dict(request.query_params)
    b = base_url(request)

    client_id = q.get("client_id") or cfg("CLIENT_ID") or b
    rt = q.get("response_type") or "id_token"
    rm = q.get("response_mode") or "direct_post"
    post_endpoint = cfg("RESPONSE_URI") or (b + "/verifier/response")
    aud_hint = q.get("aud") or "openid://"
    state = q.get("state")
    nonce = q.get("nonce")
    iat, exp = now_ts(), now_ts() + 90
    jti = secrets.token_hex(12)

    if rt == "id_token":
        payload = {
            "client_id": client_id,
            "redirect_uri": post_endpoint,
            "response_type": "id_token",
            "response_mode": rm,
            "scope": "openid",
            "state": state,
            "nonce": nonce,
            # JAR claims
            "iss": client_id,
            "aud": aud_hint,
            "iat": iat,
            "exp": exp,
            "jti": jti
        }
    else:
        # EBSI exige EXACTAMENTE 3 input_descriptors y ruta ["$.vc.type"]
        fd = {
            "path": ["$.vc.type"],
            "filter": {"type": "array", "contains": {"const": "VerifiableAttestation"}}
        }
        payload = {
            "client_id": client_id,
            "redirect_uri": post_endpoint,
            "response_type": "vp_token",
            "response_mode": rm,
            "scope": "openid",
            "state": state,
            "nonce": nonce,
            "presentation_definition": {
                "id": f"pd-{state}",
                "format": {
                    "jwt_vc": {"alg": ["ES256"]},
                    "jwt_vp": {"alg": ["ES256"]}
                },
                "input_descriptors": [
                    {"id": "va1", "format": {"jwt_vc": {"alg": ["ES256"]}}, "constraints": {"fields": [fd]}},
                    {"id": "va2", "format": {"jwt_vc": {"alg": ["ES256"]}}, "constraints": {"fields": [fd]}},
                    {"id": "va3", "format": {"jwt_vc": {"alg": ["ES256"]}}, "constraints": {"fields": [fd]}},
                ]
            },
            "vp_formats": {
                "jwt_vp": {"alg_values_supported": ["ES256"]},
                "jwt_vc": {"alg_values_supported": ["ES256"]}
            },
            # JAR claims
            "iss": client_id,
            "aud": aud_hint,
            "iat": iat,
            "exp": exp,
            "jti": jti
        }

    jws = sign_request_object(payload)  # Header: {"alg":"ES256","kid":"...","typ":"JWT"}
    return Response(content=jws, media_type="application/oauth-authz-req+jwt")

# -----------------------------
# direct_post receiver (/verifier/response)
# -----------------------------
def _extract_vp_credentials(vp_payload: Dict[str, Any]) -> List[Any]:
    vp = vp_payload.get("vp") or {}
    vcs = vp.get("verifiableCredential")
    if isinstance(vcs, list):
        return vcs
    return vp_payload.get("verifiableCredential") or []

def _parse_iso8601(s: str) -> Optional[datetime]:
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except Exception:
        return None

def _vc_is_expired(vc: Any) -> bool:
    now = int(datetime.now(tz=timezone.utc).timestamp())
    # VC-JWT (string)
    if isinstance(vc, str):
        if not jwt_decode:
            return False
        try:
            p = jwt_decode(vc, options={"verify_signature": False, "verify_exp": False})
            exp = p.get("exp")
            return isinstance(exp, (int, float)) and exp < now
        except Exception:
            return False
    # VC JSON (dict)
    if isinstance(vc, dict):
        exp = vc.get("exp")
        if isinstance(exp, (int, float)):
            return exp < now
        d = vc.get("expirationDate") or vc.get("vc", {}).get("expirationDate")
        dt = _parse_iso8601(d) if isinstance(d, str) else None
        return bool(dt and dt <= datetime.now(tz=timezone.utc))
    return False

def _index_from_descriptor_path(path: str) -> Optional[int]:
    for pat in (r'^\$\.vp\.verifiableCredential\[(\d+)\]',
                r'^\$\.verifiableCredential\[(\d+)\]'):
        m = re.match(pat, path or "")
        if m:
            return int(m.group(1))
    return None

@router.post("/verifier/response")
async def verifier_response(request: Request):
    """
    Recibe 'direct_post' desde la wallet:
      - id_token (para el test ID Token Exchange)
      - vp_token (+ presentation_submission) para VP y Expired credential
    En éxito: 302 al redirect_uri original con ?code&state
    En caso de VC expirada: 302 con error=invalid_request y el error_description exacto.
    """
    form = await request.form()
    state = form.get("state")
    id_token = form.get("id_token")
    vp_token = form.get("vp_token")
    pres_sub_raw = form.get("presentation_submission")

    fallback_redirect = cfg("REDIRECT_URI") or "openid://"

    if not state or state not in STATE_STORE:
        url = f"{fallback_redirect}?error=invalid_state&state={urllib.parse.quote(state or '')}"
        return RedirectResponse(url, 302)

    sess = STATE_STORE[state]
    final_redirect = sess.get("redirect_uri_original") or fallback_redirect

    # Guardar último resultado para UI
    LAST_RESULT.clear()
    LAST_RESULT.update({
        "state": state,
        "received": {
            "has_id_token": bool(id_token),
            "has_vp_token": bool(vp_token),
            "has_presentation_submission": bool(pres_sub_raw),
        }
    })

    got = id_token or vp_token
    if not got or got.count(".") < 2:
        url = f"{final_redirect}?error=invalid_request&state={urllib.parse.quote(state)}"
        return RedirectResponse(url, 302)

    # Caso VP: detectar expiración para el test 'Expired credential'
    if vp_token:
        try:
            vp_payload = jwt_decode(vp_token, options={"verify_signature": False, "verify_exp": False}) if jwt_decode else {}
        except Exception:
            url = f"{final_redirect}?error=invalid_request&state={urllib.parse.quote(state)}"
            return RedirectResponse(url, 302)

        vcs = _extract_vp_credentials(vp_payload)
        LAST_RESULT["vp_decoded"] = vp_payload

        pres_sub = None
        try:
            pres_sub = json.loads(pres_sub_raw) if pres_sub_raw else None
        except Exception:
            pres_sub = None

        if pres_sub and isinstance(pres_sub, dict):
            dmap = pres_sub.get("descriptor_map") or []
            LAST_RESULT["presentation_submission"] = pres_sub
            for i, d in enumerate(dmap):
                idx = _index_from_descriptor_path((d or {}).get("path"))
                if idx is not None and 0 <= idx < len(vcs) and _vc_is_expired(vcs[idx]):
                    err = f"\"presentation_submission.descriptor_map[{i}].id\" is expired"
                    url = f"{final_redirect}?error=invalid_request&error_description={urllib.parse.quote(err)}&state={urllib.parse.quote(state)}"
                    return RedirectResponse(url, 302)

        # Fallback por si no hay descriptor_map: revisa todas y devuelve el primer índice caducado
        for i, vc in enumerate(vcs):
            if _vc_is_expired(vc):
                err = f"\"presentation_submission.descriptor_map[{i}].id\" is expired"
                url = f"{final_redirect}?error=invalid_request&error_description={urllib.parse.quote(err)}&state={urllib.parse.quote(state)}"
                return RedirectResponse(url, 302)

    # ÉXITO (ID token exchange o VP válida): redirección final con code&state
    code = secrets.token_hex(24)
    url = f"{final_redirect}?code={urllib.parse.quote(code)}&state={urllib.parse.quote(state)}"
    LAST_RESULT["success_redirect"] = url
    return RedirectResponse(url, 302)

# -----------------------------
# Utilidades de depuración
# -----------------------------
@router.get("/verifier/ready")
async def verifier_ready():
    return PlainTextResponse("Verifier ready: waiting for direct_post at /verifier/response")

@router.get("/verifier/state/{state}")
async def peek_state(state: str):
    data = STATE_STORE.get(state)
    return JSONResponse({"ok": bool(data), "data": data})

@router.get("/verifier/last-result")
async def last_result():
    return JSONResponse(LAST_RESULT or {"info": "no result yet"})
