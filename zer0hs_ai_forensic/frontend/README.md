# Frontend: ZAR0HS-AI-FORENSIC

React (Vite) frontend for the analysis pipeline described in the backend.

## Setup

```bash
npm install
cp .env.development .env.development.local   # optional, only if overriding defaults
```

`.env.development` already points `VITE_API_URL` at `http://localhost:8000`
for local development. `VITE_API_KEY` should match the backend's `API_KEY`
if you've set one (see `backend/.env.example`) — leave both unset for
local development against a backend with no key configured.

## Run

```bash
npm run dev
```

Requires the backend running separately on port 8000 (see
`../backend/README.md`).

## Build

```bash
npm run build
```

Output goes to `dist/`. `vite.config.js` sets `base: '/zer0hs_ai_forensic/'`,
so a production build expects to be served from that path, not the
server root — see `Dockerfile` and `nginx.conf` for how that's handled in
the Docker image.

## Structure

- `src/App.jsx`: layout (sidebar + top status bar) and tab routing between
  the five screens (Analyze, Threat Intel, URL Sandbox, Case History,
  Accuracy).
- `src/components/ui/`: shared components (`Card`, `Badge`, `StatTile`,
  `Button`, `TabBar`, `KeyValueTable`) and `severity.js`, the single
  source of truth for severity-to-color mapping used everywhere a
  critical/high/medium/low/clean badge appears.
- `src/api.js`: the one place the backend URL and API key are read from
  environment variables — every component imports `apiClient` from here
  rather than hardcoding a URL.
