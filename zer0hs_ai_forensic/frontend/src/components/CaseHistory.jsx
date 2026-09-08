import { useEffect, useMemo, useState } from 'react'
import { ChevronDown, ChevronRight, History } from 'lucide-react'
import { apiClient } from '../api'
import Card from './ui/Card'
import SeverityBadge from './ui/SeverityBadge'
import TabBar from './ui/TabBar'
import { severityConfig } from './ui/severity'

const FILTERS = [
  ['all', 'All'],
  ['TP', 'TP'],
  ['FP', 'FP'],
  ['NEEDS_REVIEW', 'Needs Review'],
]

export default function CaseHistory() {
  const [cases, setCases]       = useState(null)
  const [error, setError]       = useState(null)
  const [expanded, setExpanded] = useState(null)
  const [filter, setFilter]     = useState('all')

  useEffect(() => {
    apiClient.get('/cases', { params: { limit: 100 } })
      .then(r => setCases(r.data.cases))
      .catch(() => setError('Could not load case history — is the backend running?'))
  }, [])

  const filtered = useMemo(() => {
    if (!cases) return cases
    if (filter === 'all') return cases
    return cases.filter(c => c.llm_verdict === filter)
  }, [cases, filter])

  const needsReviewCount = cases?.filter(c => c.llm_verdict === 'NEEDS_REVIEW').length || 0

  return (
    <div>
      <PageHeader
        title="Case History"
        subtitle="Every analysis is saved (metadata and results only — never the raw evidence text) so you can review verdicts and correct them over time."
      />

      {error && <ErrorBanner message={error} />}

      {cases === null && !error && <SkeletonList />}

      {cases?.length === 0 && (
        <EmptyState
          icon={History}
          title="No cases yet"
          body="Run an analysis from the Analyze tab — it'll show up here automatically."
        />
      )}

      {cases?.length > 0 && (
        <>
          <div style={{ marginBottom: 'var(--space-4)', borderRadius: 'var(--radius-md)', overflow: 'hidden', border: '1px solid var(--border)' }}>
            <TabBar
              tabs={FILTERS.map(([key, label]) => [
                key, key === 'NEEDS_REVIEW' && needsReviewCount > 0 ? `${label} (${needsReviewCount})` : label,
              ])}
              value={filter}
              onChange={setFilter}
            />
          </div>

          {filtered.length === 0 ? (
            <EmptyState
              icon={History}
              title="No cases match this filter"
              body="Try a different filter, or check back after analyzing more email."
            />
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
              {filtered.map(c => (
                <CaseRow
                  key={c.case_id}
                  data={c}
                  open={expanded === c.case_id}
                  onToggle={() => setExpanded(expanded === c.case_id ? null : c.case_id)}
                />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}

function CaseRow({ data, open, onToggle }) {
  const isNeedsReview = data.llm_verdict === 'NEEDS_REVIEW'
  const isTP = data.llm_verdict === 'TP'
  const c = severityConfig(isNeedsReview ? 'needs_review' : data.llm_risk_level)

  return (
    <Card padding="0" style={{ overflow: 'hidden', border: isNeedsReview ? `1px solid ${c.border}` : undefined }}>
      <button
        type="button"
        onClick={onToggle}
        style={{
          width: '100%', display: 'flex', alignItems: 'center', gap: 'var(--space-4)',
          padding: 'var(--space-4) var(--space-5)', background: 'transparent',
          border: 'none', cursor: 'pointer', textAlign: 'left',
        }}
      >
        {open ? <ChevronDown size={14} color="var(--text3)" /> : <ChevronRight size={14} color="var(--text3)" />}

        <span style={{
          fontSize: 'var(--text-sm)', fontFamily: 'var(--font-mono)', color: 'var(--text3)',
          minWidth: '150px',
        }}>
          {data.case_id}
        </span>

        <span style={{
          fontSize: 'var(--text-base)', fontWeight: 700,
          color: isNeedsReview ? c.color : (isTP ? '#fca5a5' : '#6ee7b7'), minWidth: '64px',
        }}>
          {isNeedsReview ? 'REVIEW' : (data.llm_verdict || '—')}
        </span>

        <SeverityBadge severity={isNeedsReview ? 'needs_review' : data.llm_risk_level} size="sm" />

        <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text2)' }}>
          {data.llm_confidence ?? '—'}% confidence
        </span>

        <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text3)', marginLeft: 'auto' }}>
          {data.human_verdict
            ? `reviewed — marked ${data.human_correct ? 'correct' : 'incorrect'}`
            : 'not yet reviewed'}
        </span>

        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text3)', fontFamily: 'var(--font-mono)' }}>
          {formatTimestamp(data.timestamp)}
        </span>
      </button>

      {open && (
        <div style={{ padding: '0 var(--space-5) var(--space-5)', borderTop: '1px solid var(--border)', paddingTop: 'var(--space-4)' }}>
          {data.review_reason && (
            <div style={{
              padding: '10px 14px', background: 'rgba(168,85,247,0.08)',
              border: '1px solid rgba(168,85,247,0.25)', borderRadius: 'var(--radius-sm)',
              marginBottom: 'var(--space-4)',
            }}>
              <p style={{ fontSize: 'var(--text-xs)', color: c.color, fontWeight: 600, marginBottom: '4px' }}>Why this needs a human:</p>
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text2)', lineHeight: 1.6 }}>{data.review_reason}</p>
            </div>
          )}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-4)' }}>
            <div>
              <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text3)', marginBottom: 'var(--space-2)', textTransform: 'uppercase' }}>Indicators</p>
              <IndicatorSummary indicators={data.indicators} />
            </div>
            <div>
              <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text3)', marginBottom: 'var(--space-2)', textTransform: 'uppercase' }}>Rule engine</p>
              <p style={{ fontSize: 'var(--text-base)', color: 'var(--text2)' }}>
                Rule score: <span style={{ color: 'var(--text1)', fontFamily: 'var(--font-mono)' }}>{data.rule_score ?? 0}/100</span>
              </p>
              <p style={{ fontSize: 'var(--text-base)', color: 'var(--text2)' }}>
                Anomalies detected: <span style={{ color: 'var(--text1)', fontFamily: 'var(--font-mono)' }}>{data.anomaly_count ?? 0}</span>
              </p>
              {data.human_notes && (
                <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text3)', marginTop: 'var(--space-2)', fontStyle: 'italic' }}>
                  "{data.human_notes}"
                </p>
              )}
            </div>
          </div>
        </div>
      )}
    </Card>
  )
}

function IndicatorSummary({ indicators }) {
  if (!indicators) return <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text3)' }}>None recorded</p>
  const entries = [
    ['IPs', indicators.ips],
    ['Domains', indicators.domains],
    ['URLs', indicators.urls],
    ['Emails', indicators.emails],
  ].filter(([, v]) => v?.length)

  if (entries.length === 0) return <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text3)' }}>None found</p>

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
      {entries.map(([label, values]) => (
        <p key={label} style={{ fontSize: 'var(--text-sm)', color: 'var(--text2)' }}>
          {label}: <span style={{ color: 'var(--text1)', fontFamily: 'var(--font-mono)' }}>{values.join(', ')}</span>
        </p>
      ))}
    </div>
  )
}

function formatTimestamp(iso) {
  if (!iso) return ''
  try {
    return new Date(iso).toLocaleString()
  } catch {
    return iso
  }
}

export function PageHeader({ title, subtitle }) {
  return (
    <div style={{ marginBottom: 'var(--space-6)' }}>
      <h1 style={{
        fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--text1)',
        letterSpacing: '-0.03em', marginBottom: 'var(--space-2)',
      }}>{title}</h1>
      {subtitle && <p style={{ fontSize: 'var(--text-base)', color: 'var(--text2)', lineHeight: 1.6, maxWidth: '640px' }}>{subtitle}</p>}
    </div>
  )
}

export function ErrorBanner({ message }) {
  return (
    <div style={{
      padding: '14px 16px', background: 'rgba(239,68,68,0.08)',
      border: '1px solid rgba(239,68,68,0.3)', borderRadius: 'var(--radius-md)',
      color: '#fca5a5', fontSize: 'var(--text-base)', marginBottom: 'var(--space-4)',
    }}>
      {message}
    </div>
  )
}

export function EmptyState({ icon: Icon, title, body }) {
  return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center',
      padding: 'var(--space-6) var(--space-4)', color: 'var(--text3)',
      border: '1px dashed var(--border)', borderRadius: 'var(--radius-lg)',
    }}>
      {Icon && <Icon size={28} style={{ marginBottom: 'var(--space-3)', opacity: 0.6 }} />}
      <p style={{ fontSize: 'var(--text-md)', color: 'var(--text2)', fontWeight: 600, marginBottom: '4px' }}>{title}</p>
      <p style={{ fontSize: 'var(--text-base)', maxWidth: '360px' }}>{body}</p>
    </div>
  )
}

export function SkeletonList({ rows = 4 }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} style={{
          height: '56px', borderRadius: 'var(--radius-lg)',
          background: 'linear-gradient(90deg, var(--bg2) 25%, var(--bg3) 37%, var(--bg2) 63%)',
          backgroundSize: '400% 100%',
          animation: 'skeleton-pulse 1.4s ease infinite',
        }} />
      ))}
    </div>
  )
}
