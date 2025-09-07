# app/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import holder, verifier_ebsi, presentations, ebsi_bridge

app = FastAPI(
    title="Wallet Serverless API",
    description=(
        "Minimal FastAPI service for local wallet storage (did:jwk), "
        "EBSI-style verifier endpoints (JAR + direct_post), and VP building."
    ),
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://172.28.243.230:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(holder.router, prefix="/holder", tags=["holder"])
app.include_router(verifier_ebsi.router, tags=["verifier"])
app.include_router(presentations.router, tags=["presentations"])
app.include_router(ebsi_bridge.router, tags=["bridge"])  

@app.get("/health")
def health():
    return {"ok": True}
