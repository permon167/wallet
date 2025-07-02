from fastapi import FastAPI, Body, Request
from fastapi.middleware.cors import CORSMiddleware
from mangum import Mangum
from app.services import did, credential, wallet, verifier
from pydantic import BaseModel
from typing import Dict, List, Optional

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
class CredentialPreviewAttr(BaseModel):
    name: str
    value: str

class ProposeRequest(BaseModel):
    holder_did: str
    credential_preview: List[CredentialPreviewAttr]

@app.post("/issue/propose")
def propose_credential(data: ProposeRequest):
    attributes = [attr.dict() for attr in data.credential_preview]
    return credential.propose_credential(attributes, holder_did=data.holder_did)


# Proceso request -> issue
class RequestCredentialData(BaseModel):
    holder_did: str
    password : str
    attributes: List[CredentialPreviewAttr]

@app.post("/issue/request")
def request_credential(data: RequestCredentialData):
    attributes = [attr.dict() for attr in data.attributes]
    payload = {
        "holder_did": data.holder_did,
        "attributes": attributes,
        "password": data.password  # 🆕
    }
    return credential.request_credential(payload)



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




#lambda handler
def lambda_handler(event, context):
    return handler(event, context)



# ⬇️ Esto debe ir al final
handler = Mangum(app)
