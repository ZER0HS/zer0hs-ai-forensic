# Deployment

## Local (recommended default)

Run the backend and frontend directly — see `zer0hs_ai_forensic/backend/README.md`
and `zer0hs_ai_forensic/frontend/README.md`. This is the right choice for a
single user or a small team on one machine: email content never leaves
the machine when `LLM_PROVIDER=ollama` (the default), and there's no
container overhead.

## Docker Compose

For a reproducible deploy (a shared team box, a homelab server) or to run
the backend and frontend as long-lived services:

```bash
cd zer0hs_ai_forensic
cp backend/.env.example backend/.env
# fill in real values, and set API_KEY if this will be reachable by
# more than just you

docker compose up --build
```

- Frontend: http://localhost:8080 (redirects to `/zer0hs_ai_forensic/`,
  matching the app's configured base path)
- Backend: http://localhost:8000

By default the backend container reaches **Ollama running on the host**
via `host.docker.internal` (already wired in `docker-compose.yml`) — install
Ollama on the host normally, you don't need to containerize it too. Set
`OLLAMA_URL` in `backend/.env` if Ollama runs elsewhere (a separate GPU box,
its own container on the same Docker network, etc.).

To point the frontend at a different backend origin than the default
(e.g. deploying frontend and backend on different hosts), set `VITE_API_URL`
before building — it's baked into the JS bundle at build time, not
read at container runtime:

```bash
VITE_API_URL=https://zer0hs-api.example.com docker compose up --build
```

(run from `zer0hs_ai_forensic/`, where `docker-compose.yml` lives alongside
`backend/` and `frontend/`)

Case history persists across container restarts via the `backend_feedback`
named volume.

## Cloud

The middle ground that keeps "email content never leaves a server you
control": run the backend (and optionally the frontend) on a cloud VM you
control, but keep `LLM_PROVIDER=ollama` pointed at a GPU instance you also
control, rather than switching to `LLM_PROVIDER=claude`. If you do want
Claude, it's an explicit opt-in via `.env` — nothing else changes.

Whichever route: put a reverse proxy with TLS in front of the backend,
set `API_KEY` and `CORS_ORIGINS` in `backend/.env` to your real frontend
origin (never `"*"` past localhost), and keep secrets as host/orchestrator
environment variables — never a committed `.env` file.
