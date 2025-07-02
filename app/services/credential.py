import uuid
import json
import os
from datetime import datetime
from . import wallet, did_key  # Asegúrate de tener el módulo did_key.py creado

# 👉 Claves del emisor reales (puedes moverlas a config segura)
# Cargar el archivo de identidad del emisor
ISSUER_PATH = os.path.join("data", "issuer_identity.json")

with open(ISSUER_PATH) as f:
    _issuer = json.load(f)

ISSUER_DID = _issuer["did"]
ISSUER_PRIVKEY_B64 = _issuer["privateKeyBase64"]
# ---------------------------------------------------------

def issue_credential(issuer_did: str, subject_did: str, course: str, name: str = "Usuario Anónimo"):
    vc = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "id": f"urn:uuid:{uuid.uuid4()}",
        "type": ["VerifiableCredential", "CourseCredential"],
        "issuer": issuer_did,
        "issuanceDate": datetime.utcnow().isoformat() + "Z",
        "credentialSubject": {
            "id": subject_did,
            "name": name,
            "course": course,
            "completionDate": datetime.utcnow().date().isoformat()
        },
        "proof": {
            "type": "Ed25519Signature2020",
            "created": datetime.utcnow().isoformat() + "Z",
            "proofPurpose": "assertionMethod",
            "verificationMethod": issuer_did + "#key-1",
            "jws": f"simulada-{uuid.uuid4().hex[:16]}"
        }
    }
    return vc

# ---------------------------------------------------------

def propose_credential(preview_attributes: list[dict], holder_did: str, issuer_did: str = "did:example:issuer") -> dict:
    supported_schema = {
        "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        "attributes": ["grado", "dni", "titulo", "curso"]
    }

    proposed_names = {a["name"] for a in preview_attributes}
    if not proposed_names.issubset(set(supported_schema["attributes"])):
        return {"error": "Schema not supported"}

    offer_attachment = {
        "id": "cred-1",
        "mime-type": "application/json",
        "data": {
            "json": {
                "type": supported_schema["type"],
                "credentialSubject": {a["name"]: a["value"] for a in preview_attributes}
            }
        }
    }

    offer_msg = {
        "@type": "https://didcomm.org/issue-credential/2.0/offer-credential",
        "comment": "Oferta basada en tu propuesta",
        "replacement_id": f"replace-{uuid.uuid4().hex[:8]}",
        "offers~attach": [offer_attachment]
    }

    return offer_msg

# ---------------------------------------------------------

def request_credential(request_data: dict) -> dict:
    holder_did = request_data.get("holder_did")
    attributes = request_data.get("attributes", [])
    password = request_data.get("password")

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

    # 🔐 Firma real con clave privada del emisor
    jws = did_key.sign_json(vc, ISSUER_PRIVKEY_B64)

    # 📎 Adjuntar prueba real
    vc["proof"] = {
        "type": "Ed25519Signature2020",
        "created": datetime.utcnow().isoformat() + "Z",
        "proofPurpose": "assertionMethod",
        "verificationMethod": ISSUER_DID + "#key-1",
        "jws": jws
    }

    # 💾 Guardar cifrado
    wallet.store_credential(holder_did, vc, password)

    return {
        "@type": "https://didcomm.org/issue-credential/2.0/issue-credential",
        "credentials~attach": [
            {
                "id": "cred-1",
                "mime-type": "application/json",
                "data": {"json": vc}
            }
        ]
    }
