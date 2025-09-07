# Wallet Backend y Frontend

Este proyecto incluye un backend **FastAPI** y un frontend **React/Vite** para gestionar credenciales verificables.

## Backend

1. Instalar dependencias:

```bash
pip install -r requirements.txt
```

2. Iniciar servidor:

```bash
uvicorn app.main:app --reload
```

La documentación interactiva estará disponible en `http://localhost:8000/docs`.

## Frontend

1. Instalar dependencias:

```bash
cd frontend/holder-app
npm install
```

2. Ejecutar en modo desarrollo:

```bash
npm run dev
```

Configura la variable de entorno `VITE_FASTAPI_URL` (por defecto `http://localhost:8000`) en un archivo `.env`.

## Flujo de uso

1. Crear DID desde la interfaz y definir una contraseña de la wallet.
2. Recibir credenciales introduciendo la `credential_offer_uri` del emisor.
3. Listar credenciales almacenadas, presentarlas o eliminarlas.
4. Presentar una credencial genera un `vp_jwt` listo para ser verificado.

