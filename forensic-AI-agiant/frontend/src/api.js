import axios from 'axios'

// Single source of truth for where the backend lives and how we authenticate
// to it. Every component imports `apiClient` (or `API_BASE`) from here instead
// of hardcoding a URL — see IMPLEMENTATION_PLAN.md Stage 1.
export const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

// Shared secret for the backend's X-API-Key check (see backend/main.py).
// NOTE: anything shipped in a Vite build is visible to anyone who opens the
// page — this is a deterrent for a personal/small-team local tool, not real
// authentication. Don't rely on it once this is exposed beyond localhost.
const API_KEY = import.meta.env.VITE_API_KEY || ''

export const apiClient = axios.create({
  baseURL: API_BASE,
  headers: API_KEY ? { 'X-API-Key': API_KEY } : {},
})

export const analyzeEvidence = async (file, text) => {
  const form = new FormData()
  if (file) form.append('file', file)
  if (text) form.append('text', text)
  const { data } = await apiClient.post('/analyze', form)
  return data
}
