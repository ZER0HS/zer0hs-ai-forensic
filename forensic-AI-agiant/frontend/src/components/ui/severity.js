import { AlertCircle, AlertTriangle, CircleHelp, Info, ShieldAlert, ShieldCheck } from 'lucide-react'

// Single canonical severity → {color, bg, border, badge, icon, label}
// mapping. Before this, ThreatChecker.jsx, EmailHeaders.jsx, and
// VerdictBanner.jsx each hand-rolled their own version of this same color
// function — this is the one source of truth every component imports
// instead.
//
// `needs_review` is keyed here too even though it's a verdict, not a risk
// level — a NEEDS_REVIEW case has no risk_level of its own, and reusing
// this same lookup keeps every badge in the app going through one place.
// It's deliberately violet: distinct from every actual severity color so
// it never reads as "medium risk" or any other real risk level.
export const SEVERITY = {
  critical: { color: '#fca5a5', accent: '#ef4444', bg: 'rgba(239,68,68,0.08)',  border: 'rgba(239,68,68,0.3)',  badge: 'rgba(239,68,68,0.2)',  icon: ShieldAlert,   label: 'Critical' },
  high:     { color: '#fdba74', accent: '#f97316', bg: 'rgba(249,115,22,0.08)', border: 'rgba(249,115,22,0.3)', badge: 'rgba(249,115,22,0.2)', icon: AlertTriangle, label: 'High' },
  medium:   { color: '#fcd34d', accent: '#f59e0b', bg: 'rgba(245,158,11,0.08)', border: 'rgba(245,158,11,0.3)', badge: 'rgba(245,158,11,0.2)', icon: AlertCircle,   label: 'Medium' },
  low:      { color: '#93c5fd', accent: '#3b82f6', bg: 'rgba(59,130,246,0.08)', border: 'rgba(59,130,246,0.3)', badge: 'rgba(59,130,246,0.2)', icon: Info,          label: 'Low' },
  clean:    { color: '#6ee7b7', accent: '#10b981', bg: 'rgba(16,185,129,0.08)', border: 'rgba(16,185,129,0.3)', badge: 'rgba(16,185,129,0.2)', icon: ShieldCheck,   label: 'Clean' },
  needs_review: { color: '#d8b4fe', accent: '#a855f7', bg: 'rgba(168,85,247,0.08)', border: 'rgba(168,85,247,0.3)', badge: 'rgba(168,85,247,0.2)', icon: CircleHelp, label: 'Needs Review' },
}

export function severityConfig(level) {
  return SEVERITY[level] || SEVERITY.low
}

// Abuse/risk scores (0-100) → the same severity buckets, for anywhere a
// raw numeric score needs a color (AbuseIPDB score, VirusTotal score, ...).
export function scoreToSeverity(score) {
  if (score >= 75) return 'critical'
  if (score >= 50) return 'high'
  if (score >= 25) return 'medium'
  if (score >= 10) return 'low'
  return 'clean'
}
