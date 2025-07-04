from datetime import datetime

# Almacenamiento simple en memoria para mensajes DIDComm
messages = {}

def store_message(thread_id: str, msg_type: str, sender: str, receiver: str, payload: dict, state: str = "pending"):
    messages[thread_id] = {
        "type": msg_type,
        "from": sender,
        "to": receiver,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "payload": payload,
        "state": state,
        "thread_id": thread_id
    }

def get_message(thread_id: str):
    return messages.get(thread_id)

def update_message_state(thread_id: str, new_state: str):
    if thread_id in messages:
        messages[thread_id]["state"] = new_state
