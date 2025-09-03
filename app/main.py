import os
import re
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import RedirectResponse

from app.routers import holder, oid4vc, verifier_ebsi, presentations

ALLOWED_HOSTS = [h for h in os.getenv("ALLOWED_HOSTS", "*").split(",") if h]
SERVER_BASE_URL = os.getenv("SERVER_BASE_URL", "").rstrip("/")
SESSION_SECRET = os.getenv("SESSION_SECRET", "dev-secret")  # cambia en prod

app = FastAPI(title="SSI Wallet Backend", version="1.0")

# Respeta X-Forwarded-* (ngrok/reverse proxy) -> URLs https correctas
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")

# Restringe hosts en prod (en dev puedes dejar "*")
if ALLOWED_HOSTS != ["*"]:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)

# CORS
allow_origins = [
    "https://hub.ebsi.eu",
    "http://localhost:3000",
    "https://localhost:3000",
    "http://localhost:5173",
]
# En dev puedes añadir "*" si lo necesitas:
if os.getenv("CORS_ALLOW_ALL", "false").lower() == "true":
    allow_origins.append("*")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Location"],
    max_age=86400,
)

# Routers
app.include_router(holder.router, prefix="/holder")
app.include_router(oid4vc.router)
app.include_router(verifier_ebsi.router)
app.include_router(presentations.router)

# Normaliza: '//' -> '/' y quita barra final salvo raíz
@app.middleware("http")
async def normalize_path(request: Request, call_next):
    path = re.sub(r"/{2,}", "/", request.scope.get("path", ""))
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    request.scope["path"] = path
    return await call_next(request)

@app.get("/")
def root():
    # Calidad de vida: docs por defecto
    return RedirectResponse("/docs", status_code=302)

@app.get("/health")
def health():
    return {
        "status": "ok",
        "server_base_url": SERVER_BASE_URL,
        "ngrok_configured": SERVER_BASE_URL.startswith("https://"),
    }
