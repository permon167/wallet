import json
import logging

import httpx
from fastapi import APIRouter, Request, Form
from fastapi.responses import JSONResponse, PlainTextResponse
from urllib.parse import urlparse, parse_qs, unquote

from app.services import holder

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("/holder/receive-oid4vc")
async def receive_oid4vc(request: Request):
    try:
        body = await request.json()
        logger.debug("OID4VC offer received for holder DID %s", body.get("holder_did"))

        offer_uri = body["credential_offer_uri"]
        holder_did = body["holder_did"]
        password = body["password"]

        # Extraer el parámetro credential_offer del URI
        parsed = urlparse(offer_uri)
        query = parse_qs(parsed.query)
        offer_raw = query.get("credential_offer")
        if not offer_raw:
            return JSONResponse(status_code=400, content={"error": "credential_offer no encontrado en URI"})

        offer = json.loads(unquote(offer_raw[0]))

        issuer = offer["credential_issuer"]
        grant = offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
        pre_code = grant["pre-authorized_code"]
        credential_type = offer["credentials"][0]  # ej. "dbc2023"

        logger.debug("Pre-authorized grant processed for credential type %s", credential_type)

        async with httpx.AsyncClient() as client:
            # === Paso 1: pedir el token con el pre-authorized_code ===
            token_resp = await client.post(
                f"{issuer}/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                    "pre-authorized_code": pre_code
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )

            token_data = token_resp.json()
            if "access_token" not in token_data:
                logger.error("Unexpected response from token endpoint: %s", token_data.keys())
                return JSONResponse(status_code=500, content=token_data)

            access_token = token_data["access_token"]
            nonce = token_data.get("c_nonce")
            logger.info("Token obtained; nonce present: %s", bool(nonce))

            # === Paso 2: construir el proof of possession para did:jwk ===
            jwt_obj = holder.build_proof_of_possession_jwk(nonce=nonce, issuer=issuer)
            proof_jwt = jwt_obj["jwt"]

            logger.debug("Sending credential request for type %s", credential_type)

            # === Paso 2.5: obtener el credential_endpoint dinámicamente ===
            config_resp = await client.get(f"{issuer}/.well-known/openid-credential-issuer")
            issuer_config = config_resp.json()

            credential_endpoint = issuer_config.get("credential_endpoint")
            if not credential_endpoint:
                logger.error("credential_endpoint not found in issuer configuration")
                return JSONResponse(status_code=500, content={"error": "No credential_endpoint found"})

            logger.info("Detected credential endpoint %s", credential_endpoint)

            # === Paso 3: pedir la credencial con el proof ===
            cred_resp = await client.post(
                credential_endpoint,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json"
                },
                json={
                    "format": "jwt_vc_json",
                    "credential_type": credential_type,
		    "types": ["VerifiableCredential", "DIIPv2"],
                    "proof": {
			"jwt": proof_jwt
		    }
                }
            )

            if cred_resp.status_code == 200:
                vc = cred_resp.json()
                logger.info("Credential received for DID %s", holder_did)

                # Guardar la credencial
                result = holder.store_credential(holder_did, vc, password)
                return {"message": "Credencial recibida y guardada", "result": result}
            else:
                logger.error("Error requesting credential: status %s", cred_resp.status_code)
                return JSONResponse(status_code=500, content={"error": "Credencial no recibida"})

    except Exception:
        logger.exception("General error in OID4VC flow")
        return JSONResponse(status_code=500, content={"error": "Internal server error"})

