import uuid
import os
import json
from fastapi import FastAPI, Body, Request
from fastapi.middleware.cors import CORSMiddleware
from mangum import Mangum
from app.services import did, credential, wallet, verifier, messaging, messaging_sqlite, did_key
from pydantic import BaseModel
from typing import Dict, List, Optional
from fastapi import FastAPI, Body, Request, HTTPException, Query, APIRouter
from app.services.messaging_sqlite import store_message, get_message, update_message_state
from app.services.credential import ISSUER_DID
from datetime import datetime
from app.services.credential import ISSUER_PRIVKEY_B64

messaging_sqlite.init_db()

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/messages")
def list_messages(
    did: Optional[str] = Query(None, description="DID del emisor o receptor"),
    state: Optional[str] = Query(None, description="Estado del mensaje"),
) -> List[dict]:
    result = []

    for msg in messages.values():
        if did and did not in (msg["from"], msg["to"]):
            continue
        if state and msg["state"] != state:
            continue
        result.append(msg)

    return result


@app.get("/messages/{thread_id}")
def read_message(thread_id: str):
    msg = get_message(thread_id)
    if not msg:
        raise HTTPException(status_code=404, detail="Mensaje no encontrado")
    return msg

@app.get("/create-did")
def create_did():
    return did.create_did()

class VCRequest(BaseModel):
    issuer_did: str
    subject_did: str
    course: str
    name: str = "Usuario Anónimo"

@app.post("/issue-credential")
def issue_vc(data: VCRequest):
    return credential.issue_credential(
        issuer_did=data.issuer_did,
        subject_did=data.subject_did,
        course=data.course,
        name=data.name
    )

@app.post("/store-credential")
def store_credential(did: str = Body(...), vc: Dict = Body(...)):
    return wallet.store_credential(did, vc)

class WalletListRequest(BaseModel):
    did: str
    password: str

@app.post("/wallet/list")
def list_wallet(data: WalletListRequest):
    return wallet.list_credentials(did=data.did, password=data.password)

from fastapi import Request

@app.post("/verify-credential")
async def verify_credential(request: Request):
    vp = await request.json()
    return verifier.verify_credential(vp)

# 🔹 NUEVO ENDPOINT para RFC 0453
class ProposeRequest(BaseModel):
    holder_did: str
    credential_preview: list[dict]

@app.post("/issue/propose")
def propose_credential(data: ProposeRequest):
    thread_id = str(uuid.uuid4())

    # Guardar mensaje propose-credential en SQLite
    store_message(thread_id, "propose-credential", data.holder_did, ISSUER_DID, {
        "credential_preview": data.credential_preview
    })

    offer_attachment = {
        "id": "cred-1",
        "mime-type": "application/json",
        "data": {
            "json": {
                "type": ["VerifiableCredential", "UniversityDegreeCredential"],
                "credentialSubject": {a["name"]: a["value"] for a in data.credential_preview}
            }
        }
    }

    offer_msg = {
        "@type": "https://didcomm.org/issue-credential/2.0/offer-credential",
        "thread_id": thread_id,
        "comment": "Oferta basada en tu propuesta",
        "replacement_id": f"replace-{uuid.uuid4().hex[:8]}",
        "offers~attach": [offer_attachment]
    }

    # Guardar mensaje offer-credential en SQLite
    store_message(thread_id, "offer-credential", ISSUER_DID, data.holder_did, offer_msg)

    return offer_msg

# Proceso request -> issue

class RequestCredentialData(BaseModel):
    holder_did: str
    password: str
    attributes: list[dict]
    thread_id: str

@app.post("/issue/request")
def request_credential(data: RequestCredentialData):
    proposal_msg = get_message(data.thread_id)
    if not proposal_msg or proposal_msg["type"] not in ["propose-credential", "offer-credential"]:
        return {"error": "No se encontró propuesta u oferta válida con ese thread_id"}

    vc = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        "issuer": ISSUER_DID,
        "issuanceDate": datetime.utcnow().isoformat() + "Z",
        "credentialSubject": {
            "id": data.holder_did,
            **{a["name"]: a["value"] for a in data.attributes}
        },
        "thread_id": data.thread_id  # <-- Añadido para trazabilidad
    }

    jws = did_key.sign_json(vc, ISSUER_PRIVKEY_B64)

    vc["proof"] = {
        "type": "Ed25519Signature2020",
        "created": datetime.utcnow().isoformat() + "Z",
        "proofPurpose": "assertionMethod",
        "verificationMethod": ISSUER_DID + "#key-1",
        "jws": jws
    }

    wallet.store_credential(data.holder_did, vc, data.password)

    store_message(data.thread_id, "issue-credential", ISSUER_DID, data.holder_did, vc, state="done")

    return {
        "@type": "https://didcomm.org/issue-credential/2.0/issue-credential",
        "thread_id": data.thread_id,
        "credentials~attach": [
            {
                "id": "cred-1",
                "mime-type": "application/json",
                "data": {"json": vc}
            }
        ]
    }
##------------------------------------------------------


class PresentRequest(BaseModel):
    holder_did: str
    password: str
    index: Optional[int] = 0  # índice de la credencial a presentar

@app.post("/present")
def present_vp(data: PresentRequest):
    return wallet.present_credential(
        holder_did=data.holder_did,
        password=data.password,
        index=data.index
    )

class DeleteCredentialRequest(BaseModel):
    did: str
    password: str
    index: int

@app.delete("/wallet/delete_credential")
def delete_credential(data: DeleteCredentialRequest = Body(...)):
    path = wallet._get_wallet_path(data.did)

    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Wallet no encontrada")

    with open(path, "r") as f:
        enc_data = json.load(f)

    try:
        credentials = wallet._decrypt_json(enc_data, data.password)
    except Exception:
        raise HTTPException(status_code=400, detail="Contraseña incorrecta o datos corruptos")

    if data.index < 0 or data.index >= len(credentials):
        raise HTTPException(status_code=400, detail="Índice de credencial fuera de rango")

    credentials.pop(data.index)

    enc_data_new = wallet._encrypt_json(credentials, data.password)

    with open(path, "w") as f:
        json.dump(enc_data_new, f, indent=2)

    return {"message": "Credencial eliminada correctamente", "total": len(credentials)}




#lambda handler
def lambda_handler(event, context):
    return handler(event, context)



# ⬇️ Esto debe ir al final
handler = Mangum(app)
