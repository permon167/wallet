import uuid
import json
import os
from datetime import datetime
from . import wallet, did_key
from .messaging import store_message, get_message, update_message_state

# 👉 Claves del emisor reales cargadas desde archivo
ISSUER_PATH = os.path.join("data", "issuer_identity.json")
with open(ISSUER_PATH) as f:
    _issuer = json.load(f)

ISSUER_DID = _issuer["did"]
ISSUER_PRIVKEY_B64 = _issuer["privateKeyBase64"]

# ---------------------------------------------------------

def propose_credential(preview_attributes: list[dict], holder_did: str) -> dict:
    thread_id = str(uuid.uuid4())

    # Guardar mensaje propose-credential
    store_message(thread_id, "propose-credential", holder_did, ISSUER_DID, {
        "credential_preview": preview_attributes
    })

    offer_attachment = {
        "id": "cred-1",
        "mime-type": "application/json",
        "data": {
            "json": {
                "type": ["VerifiableCredential", "UniversityDegreeCredential"],
                "credentialSubject": {a["name"]: a["value"] for a in preview_attributes}
            }
        }
    }

    offer_msg = {
        "@type": "https://didcomm.org/issue-credential/2.0/offer-credential",
        "thread_id": thread_id,  # <- añadir aquí
        "comment": "Oferta basada en tu propuesta",
        "replacement_id": f"replace-{uuid.uuid4().hex[:8]}",
        "offers~attach": [offer_attachment]
    }

    # Guardar mensaje offer-credential
    store_message(thread_id, "offer-credential", ISSUER_DID, holder_did, offer_msg)

    return offer_msg
# ---------------------------------------------------------

def request_credential(request_data: dict) -> dict:
    holder_did = request_data.get("holder_did")
    attributes = request_data.get("attributes", [])
    password = request_data.get("password")
    thread_id = request_data.get("thread_id")

    proposal_msg = get_message(thread_id)
    if not proposal_msg or proposal_msg["type"] not in ["propose-credential", "offer-credential"]:
        return {"error": "No se encontró propuesta u oferta válida con ese thread_id"}

    vc = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        "issuer": ISSUER_DID,
        "issuanceDate": datetime.utcnow().isoformat() + "Z",
        "credentialSubject": {
            "id": holder_did,
            **{a["name"]: a["value"] for a in attributes}
        }
    }

    jws = did_key.sign_json(vc, ISSUER_PRIVKEY_B64)

    vc["proof"] = {
        "type": "Ed25519Signature2020",
        "created": datetime.utcnow().isoformat() + "Z",
        "proofPurpose": "assertionMethod",
        "verificationMethod": ISSUER_DID + "#key-1",
        "jws": jws
    }

    wallet.store_credential(holder_did, vc, password)

    store_message(thread_id, "issue-credential", ISSUER_DID, holder_did, vc, state="done")

    return {
        "@type": "https://didcomm.org/issue-credential/2.0/issue-credential",
        "thread_id": thread_id,
        "credentials~attach": [
            {
                "id": "cred-1",
                "mime-type": "application/json",
                "data": {"json": vc}
            }
        ]
    }
