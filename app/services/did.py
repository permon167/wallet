import uuid

def create_did():
    did = f"did:key:simulada:{uuid.uuid4()}"
    key = f"clave-{uuid.uuid4().hex[:16]}"
    return {"did": did, "key": key}
