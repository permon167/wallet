Purpose
- Keep the `data/` directory in the repository without committing secrets or machine-specific files.

What stays ignored
- Private keys, wallets, and runtime artifacts remain untracked by default due to `.gitignore` rules (`data/*`).
- Only this `README.md` and `.gitkeep` are tracked.

Typical contents (local only)
- `*_wallet.json`, `*.pem`, and other key material
- Encrypted blobs like `.enc`

Notes
- Do not commit private keys or real wallet files.
- Use `.env.example` as a reference for local setup and keep your actual `.env` untracked.

