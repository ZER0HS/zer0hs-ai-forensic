# --- build stage ---
FROM node:22-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
# Baked into the JS bundle at build time (Vite env vars aren't readable at
# container runtime) — override with --build-arg for a non-default backend.
# Docker will warn that VITE_API_KEY looks like a secret in an ARG/ENV;
# that's expected here, not a leak to fix — it's a client-visible deterrent
# key by design (see api.js), so it ends up equally public in the shipped
# JS bundle no matter how it's injected at build time.
ARG VITE_API_URL=http://localhost:8000
ARG VITE_API_KEY=
ENV VITE_API_URL=$VITE_API_URL
ENV VITE_API_KEY=$VITE_API_KEY
RUN npm run build

# --- serve stage ---
FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
