from fastapi import APIRouter, Request, Form
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel
import json
import httpx
from urllib.parse import urlparse, parse_qs, unquote

from app.services import holder

router = APIRouter()

@router.post("/create-did-jwk")
async def create_did_jwk():
    identity = holder.create_did_jwk()
    return {"message": "Identidad JWK creada", "did": identity["did"]}


@router.post("/credentials")
async def get_all_credentials(request: Request):
    try:
        body = await request.json()
        holder_did = body["holder_did"]
        password = body.get("password", "default")  # usa "default" por defecto

        creds = holder.load_credentials(holder_did, password)
        return {"credentials": creds}
    except FileNotFoundError:
        return JSONResponse(status_code=404, content={"error": "Wallet no encontrada"})
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


@router.post("/delete-credential")
async def delete_credential(request: Request):
    try:
        body = await request.json()
        holder_did = body["holder_did"]
        password = body.get("password", "default")
        index = body["index"]

        creds = holder.load_credentials(holder_did, password)
        if index < 0 or index >= len(creds):
            return JSONResponse(status_code=400, content={"error": "Índice de credencial inválido"})

        del creds[index]

        from app.services.holder import _encrypt, _path
        encrypted = _encrypt(json.dumps(creds), password)

        with open(_path(holder_did), "w") as f:
            json.dump(encrypted, f, indent=2)

        return {"message": "Credencial eliminada", "total": len(creds)}
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})



@router.post("/decode-credential")
async def decode_credential(request: Request):
    try:
        body = await request.json()
        holder_did = body["holder_did"]
        password = body["password"]
        index = body.get("index", 0)

        from app.services import holder
        data = holder.decode_jwt_credential(holder_did, password, index)

        return JSONResponse(content=data)
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})



@router.post("/receive-oid4vc")
async def receive_oid4vc(request: Request):
    try:
        body = await request.json()
        print("🔍 Oferta recibida:", json.dumps(body, indent=2))

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

        print("🔐 Grant:", json.dumps(grant, indent=2))

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
                print("❌ Respuesta inesperada del token endpoint:", token_data)
                return JSONResponse(status_code=500, content=token_data)

            access_token = token_data["access_token"]
            nonce = token_data.get("c_nonce")
            print("🪪 Token OK, nonce:", nonce)

            # === Paso 2: construir el proof of possession para did:jwk ===
            jwt_obj = holder.build_proof_of_possession_jwk(nonce=nonce, issuer=issuer)
            proof_jwt = jwt_obj["jwt"]

            print("📤 Enviando solicitud de credencial con proof JWT:")
            print(json.dumps({
                "format": "jwt_vc_json",
                "credential_type": credential_type,
                "proof": proof_jwt
            }, indent=2))

            # === Paso 2.5: obtener el credential_endpoint dinámicamente ===
            config_resp = await client.get(f"{issuer}/.well-known/openid-credential-issuer")
            issuer_config = config_resp.json()

            credential_endpoint = issuer_config.get("credential_endpoint")
            if not credential_endpoint:
                print("❌ No se encontró el credential_endpoint en la configuración del issuer")
                return JSONResponse(status_code=500, content={"error": "No credential_endpoint found"})

            print("📍 Endpoint de credenciales detectado:", credential_endpoint)

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
                print("✅ Credencial recibida:", json.dumps(vc, indent=2))

                # Guardar la credencial
                result = holder.store_credential(holder_did, vc, password)
                return {"message": "Credencial recibida y guardada", "result": result}
            else:
                print("❌ Error al pedir la credencial:")
                print("🔸 Código:", cred_resp.status_code)
                print("🔸 Respuesta:", cred_resp.text)
                return JSONResponse(status_code=500, content={"error": "Credencial no recibida"})

    except Exception as e:
        print("❌ Error general:", str(e))
        return JSONResponse(status_code=500, content={"error": str(e)})
