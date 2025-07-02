import os
import json
from datetime import datetime
from typing import List
from . import did_key

# Cargar clave pública del emisor desde archivo
ISSUER_PATH = os.path.join("data", "issuer_identity.json")
with open(ISSUER_PATH) as f:
    _issuer = json.load(f)

ISSUER_PUBKEY_B58 = _issuer["publicKeyBase58"]

# Cargar clave pública del holder desde archivo
HOLDER_PATH = os.path.join("data", "holder_identity.json")
with open(HOLDER_PATH) as f:
    _holder = json.load(f)

HOLDER_PUBKEY_B58 = _holder["publicKeyBase58"]


def verify_credential(vp: dict) -> dict:
    errors: List[str] = []

    if "verifiableCredential" not in vp:
        return {"valid": False, "error": "Missing verifiableCredential"}

    vcs = vp["verifiableCredential"]
    holder = vp.get("holder")
    vp_proof = vp.get("proof", {})

    # Verificar firma de la presentación (VP)
    try:
        valid_vp = did_key.verify_json(
            data={k: vp[k] for k in vp if k != "proof"},
            signature_b64=vp_proof.get("jws", ""),
            public_key_b58=HOLDER_PUBKEY_B58
        )
    except Exception as e:
        errors.append(f"VP signature verification exception: {str(e)}")
        valid_vp = False

    if not valid_vp:
        errors.append("VP has invalid JWS signature")

    # Verificar cada credencial
    for i, vc in enumerate(vcs):
        vc_proof = vc.get("proof", {})
        subject_id = vc.get("credentialSubject", {}).get("id")

        try:
            valid_vc = did_key.verify_json(
                data={k: vc[k] for k in vc if k != "proof"},
                signature_b64=vc_proof.get("jws", ""),
                public_key_b58=ISSUER_PUBKEY_B58
            )
        except Exception as e:
            errors.append(f"VC #{i} signature exception: {str(e)}")
            continue

        if not valid_vc:
            errors.append(f"VC #{i} signature is invalid")

        if subject_id != holder:
            errors.append(f"VC #{i} subject ID does not match holder")

        try:
            issued = datetime.fromisoformat(vc["issuanceDate"].replace("Z", ""))
            if issued > datetime.utcnow():
                errors.append(f"VC #{i} issuanceDate is in the future")
        except Exception:
            errors.append(f"VC #{i} issuanceDate is invalid")

    return {
        "valid": len(errors) == 0,
        "holder": holder,
        "checked_credentials": len(vcs),
        "errors": errors
    }
