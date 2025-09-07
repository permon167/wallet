# Wallet Serverless (FastAPI)

Simple FastAPI service that demonstrates three roles around OpenID for Verifiable Credentials and EBSI testing:

- Holder: minimal encrypted wallet storage (did:jwk) and OID4VCI credential reception.
- Verifier (EBSI bridge): endpoints to generate signed authorization requests (JAR), receive direct_post results, and emulate EBSI verifier behavior for local testing.
- Presentations: build and optionally send a compact VP-JWT based on locally stored credentials.

Use this project to quickly test wallet and verifier flows locally, inspect payloads, and integrate with a simple frontend.

## Quickstart

- Requirements: Python 3.10+ and `pip`.
- Install dependencies:
  - `pip install -r requirements.txt`
- Run the API:
  - `uvicorn app.main:app --reload --port 8000`
- Open docs:
  - Swagger UI: `http://localhost:8000/docs`
  - ReDoc: `http://localhost:8000/redoc`

## Configuration (.env)

Copy `.env.example` to `.env` and adjust values if needed. Important variables:

- `SERVER_BASE_URL` — Public base URL of this server (defaults to request base in code).
- `RESPONSE_URI` — Where wallets will `direct_post` results (default: `<BASE>/verifier/response`).
- `REDIRECT_URI` — Final redirect after `direct_post` (default: `openid://`).
- `REQUEST_JWT_PRIVATE_KEY_PATH` — PEM file used to sign Request Objects (JAR). If missing, it is generated at startup under `data/`.
- `REQUEST_JWT_PRIVATE_KEY`, `REQUEST_JWT_PRIVATE_KEY_PASS` — Inline PEM and optional passphrase instead of file.
- `HOLDER_PRIVATE_PEM_PATH`, `HOLDER_PRIVATE_JWK_JSON` — Holder private key material, used by the bridge/id-proof and presentations helper.
- `DATA_DIR` — Where to store local keys and files (default: `data`).

The server stores development keys and wallet content in `data/`. Do not use this setup for production.

## Main Endpoints (quick reference)

Health
- `GET /health` — Service health check.

Holder (encrypted wallet)
- `POST /holder/create-did-jwk` — Create a new did:jwk identity and persist the private key under `data/`.
- `POST /holder/credentials` — Load all stored credentials for a given `holder_did` and `password`.
- `POST /holder/delete-credential` — Delete a credential by list index.
- `POST /holder/decode-credential` — Decode a stored VC-JWT without verifying signature.
- `POST /holder/receive-oid4vc` — OID4VCI: redeem a `credential_offer_uri`, build proof (ES256), and store received credential.

Verifier (EBSI-style)
- `GET /.well-known/openid-configuration` — Discovery document.
- `GET /jwks.json` — JWKS exposing the ES256 public key (used to sign JARs).
- `GET /authorize` — Builds an OpenID request and redirects to `openid://?...request_uri=...` (mobile wallet behavior).
- `GET /authorize/openid` — Same as above but returns JSON with `openid_url` for QR/desktop.
- `GET /request` — Returns a signed Request Object (JAR, `application/oauth-authz-req+jwt`).
- `POST /verifier/response` — Receives `direct_post` with `id_token` or `vp_token` and redirects to `REDIRECT_URI`.
- Debug: `GET /verifier/ready`, `GET /verifier/last-result`, `GET /verifier/state/{state}`.

Presentations
- `POST /wallet/present` — Build a VP-JWT from selected stored VCs and optionally `direct_post` to a verifier.

Bridge helpers
- `GET /bridge/prepare-vp` — Pre-flight check against a verifier for VP flow (state/nonce returned).
- `GET /bridge/prepare-id` — Pre-flight for ID token flow.
- `POST /holder/id-proof` — Create a simple ES256 `id_token` for the verifier and submit via `direct_post`.

## Minimal examples

Create a holder DID and key:

- `curl -X POST http://localhost:8000/holder/create-did-jwk`

List credentials in the wallet:

- `curl -X POST http://localhost:8000/holder/credentials -H 'Content-Type: application/json' -d '{"holder_did":"did:jwk:...","password":"default"}'`

Present VCs (build VP locally, do not send):

- `curl -X POST http://localhost:8000/wallet/present -H 'Content-Type: application/json' -d '{"holder_did":"did:jwk:...","password":"default","select":[0],"send":false}'`

Get an `openid://` URL for a verifier-initiated flow:

- `curl 'http://localhost:8000/authorize/openid?flow=vp'`

## Notes and caveats

- This code is for local testing and demos. Keys in `data/` are unsealed in development; secure them for any real deployment.
- Signature verification is intentionally skipped in some decode paths to aid debugging.
- Some responses and error messages are in Spanish as the original codebase; you can adjust them to your locale.

