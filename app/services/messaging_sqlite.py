import sqlite3
from datetime import datetime
import json
from typing import Optional

DB_PATH = "data/messages.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            thread_id TEXT PRIMARY KEY,
            type TEXT,
            sender TEXT,
            receiver TEXT,
            created_at TEXT,
            payload TEXT,
            state TEXT
        )
    """)
    conn.commit()
    conn.close()

def store_message(thread_id: str, msg_type: str, sender: str, receiver: str, payload: dict, state: str = "pending"):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT OR REPLACE INTO messages (thread_id, type, sender, receiver, created_at, payload, state)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        thread_id,
        msg_type,
        sender,
        receiver,
        datetime.utcnow().isoformat() + "Z",
        json.dumps(payload),
        state
    ))
    conn.commit()
    conn.close()

def get_message(thread_id: str) -> Optional[dict]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM messages WHERE thread_id = ?", (thread_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "thread_id": row[0],
        "type": row[1],
        "from": row[2],
        "to": row[3],
        "created_at": row[4],
        "payload": json.loads(row[5]),
        "state": row[6]
    }

def update_message_state(thread_id: str, new_state: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE messages SET state = ? WHERE thread_id = ?", (new_state, thread_id))
    conn.commit()
    conn.close()

def list_messages(did: Optional[str] = None, state: Optional[str] = None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    query = "SELECT * FROM messages"
    conditions = []
    params = []
    if did:
        conditions.append("(sender = ? OR receiver = ?)")
        params.extend([did, did])
    if state:
        conditions.append("state = ?")
        params.append(state)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    c.execute(query, params)
    rows = c.fetchall()
    conn.close()
    result = []
    for row in rows:
        result.append({
            "thread_id": row[0],
            "type": row[1],
            "from": row[2],
            "to": row[3],
            "created_at": row[4],
            "payload": json.loads(row[5]),
            "state": row[6]
        })
    return result
