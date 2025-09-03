from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from app.services import holder
import json  # ✅ Asegúrate de tener esto

router = APIRouter()


def _validate_password(password: str) -> None:
    """Simple password validation enforcing presence and length."""
    if not password:
        raise ValueError("Se requiere contraseña")
    if len(password) < 8:
        raise ValueError("La contraseña debe tener al menos 8 caracteres")

@router.post("/create-did-jwk")
async def create_did_jwk():
    identity = holder.create_did_jwk()
    return {"message": "Identidad JWK creada", "did": identity["did"]}

@router.post("/didcomm/signed-request")
async def signed_request(request: Request):
    body = await request.json()
    issuer_did = body.get("issuer_did")
    message = await holder.send_signed_request_to_issuer(issuer_did)
    return JSONResponse(content=message)

class StoreCredentialRequest(BaseModel):
    holder_did: str
    password: str
    message: dict

@router.post("/store-credential")
async def store_credential_endpoint(input: StoreCredentialRequest):
    try:
        _validate_password(input.password)
        result = holder.store_credential(input.holder_did, input.message, input.password)
        return {"status": "success", "message": "Credencial almacenada correctamente", "total": result.get("total", 0)}
    except ValueError as e:
        return {"status": "error", "message": str(e)}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.post("/get-latest-credential")
async def get_latest_credential(request: Request):
    try:
        body = await request.json()
        holder_did = body["holder_did"]
        password = body["password"]
        _validate_password(password)

        creds = holder.load_credentials(holder_did, password)
        if not creds:
            return JSONResponse(status_code=404, content={"error": "No hay credenciales"})

        return {"vc": creds[-1]}
    except KeyError as e:
        return JSONResponse(status_code=400, content={"error": f"Falta campo requerido: {str(e)}"})
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

@router.post("/credentials")
async def get_all_credentials(request: Request):
    try:
        body = await request.json()
        holder_did = body["holder_did"]
        password = body["password"]
        _validate_password(password)

        creds = holder.load_credentials(holder_did, password)
        return {"credentials": creds}
    except KeyError as e:
        return JSONResponse(status_code=400, content={"error": f"Falta campo requerido: {str(e)}"})
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    except FileNotFoundError:
        return JSONResponse(status_code=404, content={"error": "Wallet no encontrada"})
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


@router.post("/delete-credential")
async def delete_credential(request: Request):
    try:
        body = await request.json()
        holder_did = body["holder_did"]
        password = body["password"]
        _validate_password(password)
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
    except KeyError as e:
        return JSONResponse(status_code=400, content={"error": f"Falta campo requerido: {str(e)}"})
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})



@router.post("/present-credential-jwt")
async def present_credential_jwt(request: Request):
    try:
        data = await request.json()
        holder_did = data["holder_did"]
        password = data["password"]
        _validate_password(password)
        index = int(data.get("index", 0))
        aud = data["aud"]          # <- obligatorio
        nonce = data["nonce"]      # <- obligatorio
        header_typ = data.get("header_typ", "vp+jwt")  # opcional: "vp+jwt" | "JWT"

        from app.services import presentation
        vp_jwt = presentation.build_vp_from_wallet_index(
            holder_did=holder_did,
            password=password,
            index=index,
            aud=aud,
            nonce=nonce,
            header_typ=header_typ,
        )
        return {"vp_jwt": vp_jwt}
    except KeyError as e:
        return JSONResponse(status_code=400, content={"error": f"Falta campo requerido: {str(e)}"})
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})



@router.post("/decode-credential")
async def decode_credential(request: Request):
    try:
        body = await request.json()
        holder_did = body["holder_did"]
        password = body["password"]
        _validate_password(password)
        index = body.get("index", 0)

        from app.services import holder
        data = holder.decode_jwt_credential(holder_did, password, index)

        return JSONResponse(content=data)
    except KeyError as e:
        return JSONResponse(status_code=400, content={"error": f"Falta campo requerido: {str(e)}"})
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


@router.post("/jwt-credential")
async def get_jwt_credential(request: Request):
    """
    Devuelve el VC-JWT (string) almacenado en el índice indicado.
    Body: { "holder_did": "...", "password": "...", "index": 0 }
    """
    try:
        body = await request.json()
        holder_did = body["holder_did"]
        password = body["password"]
        _validate_password(password)
        index = int(body.get("index", 0))

        # Carga de credenciales desde tu almacenamiento
        creds = holder.load_credentials(holder_did, password)

        if not isinstance(creds, list) or len(creds) == 0:
            return JSONResponse(status_code=404, content={"error": "No hay credenciales almacenadas."})

        if index < 0 or index >= len(creds):
            return JSONResponse(status_code=400, content={"error": "Índice inválido."})

        item = creds[index]

        # Soporta varios formatos de cómo guardes la VC:
        #  - como string JWT
        #  - como dict con clave "credential" (contenido JWT)
        #  - como dict con clave "jwt"
        if isinstance(item, str):
            vc_jwt = item
        elif isinstance(item, dict) and "credential" in item and isinstance(item["credential"], str):
            vc_jwt = item["credential"]
        elif isinstance(item, dict) and "jwt" in item and isinstance(item["jwt"], str):
            vc_jwt = item["jwt"]
        else:
            return JSONResponse(
                status_code=400,
                content={"error": "La credencial del índice indicado no es un JWT en formato string."},
            )

        return {"jwt": vc_jwt}
    except KeyError as e:
        return JSONResponse(status_code=400, content={"error": f"Falta campo requerido: {str(e)}"})
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
