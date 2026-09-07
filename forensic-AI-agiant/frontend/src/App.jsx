import { useState, useEffect } from 'react'
import { AlertTriangle } from 'lucide-react'
import { analyzeEvidence, apiClient } from './api'
import FileUpload from './components/FileUpload'
import ResultsView from './components/ResultsView'
import ThreatChecker from './components/ThreatChecker'
import SandboxView from './components/SandboxView'
import CaseHistory, { ErrorBanner, PageHeader } from './components/CaseHistory'
import AccuracyDashboard from './components/AccuracyDashboard'
import Sidebar from './components/Sidebar'

export default function App() {
  const [result, setResult]     = useState(null)
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState(null)
  const [tab, setTab]           = useState('evidence')
  const [status, setStatus]     = useState(null)

  // Fetch backend status on load
  useEffect(() => {
    apiClient.get('/status')
      .then(r => setStatus(r.data))
      .catch(() => setStatus(null))
  }, [])

  async function handleAnalyze(file, text) {
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const data = await analyzeEvidence(file, text)
      setResult(data)
    } catch {
      setError('Backend error — make sure it is running on port 8000')
    }
    setLoading(false)
  }

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg0)', display: 'flex' }}>
      <Sidebar active={tab} onNavigate={setTab} />

      <div style={{ flex: 1, minWidth: 0 }}>
        <TopStatusBar status={status} />

        <div style={{ maxWidth: '1140px', margin: '0 auto', padding: 'var(--space-6) var(--space-5)' }}>

          {tab === 'evidence' && (
            <>
              <PageHeader
                title="Evidence Analysis"
                subtitle="Upload an email, log file, or paste text — the agent automatically extracts IPs, domains, checks threat intel, and delivers a full FP/TP verdict."
              />

              <FileUpload onAnalyze={handleAnalyze} loading={loading} />

              {error && <ErrorBanner message={error} />}

              {loading && <AnalysisSkeleton />}

              {result && <ResultsView data={result} />}
            </>
          )}

          {tab === 'threat' && <ThreatChecker />}

          {tab === 'sandbox' && (
            <>
              <PageHeader
                title="URL Sandbox"
                subtitle="Submit any URL to URLScan.io for live sandbox analysis — get screenshot, server info, malicious verdict, and full behavior report."
              />
              <SandboxView standalone />
            </>
          )}

          {tab === 'history'  && <CaseHistory />}
          {tab === 'accuracy' && <AccuracyDashboard />}

        </div>
      </div>
    </div>
  )
}

function TopStatusBar({ status }) {
  return (
    <div style={{
      height: 'var(--topbar-height)', display: 'flex', alignItems: 'center',
      justifyContent: 'flex-end', gap: 'var(--space-3)',
      padding: '0 var(--space-5)', borderBottom: '1px solid var(--border)',
      background: 'var(--bg1)', position: 'sticky', top: 0, zIndex: 10,
    }}>
      {status && (
        <div style={{ display: 'flex', gap: '6px' }}>
          {[
            ['AbuseIPDB', status.abuseipdb],
            ['VT',        status.virustotal],
            ['URLScan',   status.urlscan],
          ].map(([name, ok]) => (
            <span key={name} style={{
              fontSize: 'var(--text-xs)', padding: '2px 7px', borderRadius: 'var(--radius-sm)',
              background: ok ? 'rgba(16,185,129,0.1)' : 'rgba(239,68,68,0.1)',
              color: ok ? '#6ee7b7' : '#fca5a5',
              border: `1px solid ${ok ? 'rgba(16,185,129,0.2)' : 'rgba(239,68,68,0.2)'}`,
            }}>{name}</span>
          ))}
        </div>
      )}

      <div style={{
        display: 'flex', alignItems: 'center', gap: '6px',
        padding: '4px 10px', borderRadius: 'var(--radius-sm)',
        background: status?.provider_ok ? 'rgba(16,185,129,0.08)' : 'rgba(239,68,68,0.08)',
        border: `1px solid ${status?.provider_ok ? 'rgba(16,185,129,0.2)' : 'rgba(239,68,68,0.2)'}`,
      }}>
        <div style={{
          width: '5px', height: '5px', borderRadius: '50%',
          background: status?.provider_ok ? 'var(--green)' : '#ef4444',
          boxShadow: status?.provider_ok ? '0 0 6px #10b981' : '0 0 6px #ef4444',
        }} />
        <span style={{ fontSize: 'var(--text-xs)', color: status?.provider_ok ? 'var(--green)' : '#fca5a5' }}>
          {status ? `${status.provider} · ${status.model}` : 'connecting...'}
        </span>
      </div>

      {status && !status.provider_ok && status.error && (
        <span style={{
          display: 'flex', alignItems: 'center', gap: '4px',
          fontSize: 'var(--text-xs)', color: '#fca5a5', maxWidth: '220px', lineHeight: 1.4,
        }}>
          <AlertTriangle size={12} /> {status.error}
        </span>
      )}
    </div>
  )
}

// Real backend progress would need a streaming/polling endpoint the
// pipeline doesn't expose yet — until then, a skeleton is honest about
// "working" without guessing at fake step names tied to nothing real.
function AnalysisSkeleton() {
  const shimmer = {
    background: 'linear-gradient(90deg, var(--bg2) 25%, var(--bg3) 37%, var(--bg2) 63%)',
    backgroundSize: '400% 100%',
    animation: 'skeleton-pulse 1.4s ease infinite',
    borderRadius: 'var(--radius-lg)',
  }
  return (
    <div style={{ marginTop: 'var(--space-5)', display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
      <div style={{ ...shimmer, height: '96px' }} />
      <div style={{ ...shimmer, height: '260px' }} />
    </div>
  )
}
