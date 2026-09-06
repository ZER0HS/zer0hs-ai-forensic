import { useState, useEffect } from 'react'
import { analyzeEvidence, apiClient } from './api'
import FileUpload from './components/FileUpload'
import ResultsView from './components/ResultsView'
import ThreatChecker from './components/ThreatChecker'
import SandboxView from './components/SandboxView'

export default function App() {
  const [result, setResult]     = useState(null)
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState(null)
  const [tab, setTab]           = useState('evidence')
  const [progress, setProgress] = useState('')
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
    const steps = [
      'Parsing evidence...',
      'Extracting indicators...',
      'Checking threat intelligence...',
      'Running AI analysis...',
      'Scoring FP/TP verdict...'
    ]
    let i = 0
    const timer = setInterval(() => {
      setProgress(steps[Math.min(i++, steps.length - 1)])
    }, 1800)
    try {
      const data = await analyzeEvidence(file, text)
      setResult(data)
      setTab('evidence')
    } catch(e) {
      setError('Backend error — make sure it is running on port 8000')
    }
    clearInterval(timer)
    setProgress('')
    setLoading(false)
  }

  const navTabs = [
    ['evidence', 'Evidence Analysis', '🔍'],
    ['threat',   'Threat Intel',      '🛡️'],
    ['sandbox',  'URL Sandbox',       '📦'],
  ]

  return (
    <div style={{minHeight:'100vh', background:'var(--bg0)'}}>

      {/* Nav */}
      <nav style={{
        background:'var(--bg1)',
        borderBottom:'1px solid var(--border)',
        padding:'0 32px',
        display:'flex', alignItems:'center',
        position:'sticky', top:0, zIndex:100,
        backdropFilter:'blur(12px)'
      }}>

        {/* Logo */}
        <div style={{display:'flex', alignItems:'center', gap:'8px',
          marginRight:'40px', padding:'14px 0'}}>
          <div style={{
            width:'28px', height:'28px', borderRadius:'6px',
            background:'linear-gradient(135deg, #3b82f6, #8b5cf6)',
            display:'flex', alignItems:'center', justifyContent:'center',
            fontSize:'14px', fontWeight:'700', color:'white'
          }}>F</div>
          <span style={{fontSize:'14px', fontWeight:'700',
            color:'var(--text1)', letterSpacing:'-0.02em'}}>
            ForensicAI
          </span>
        </div>

        {/* Nav tabs */}
        <div style={{display:'flex', gap:'4px'}}>
          {navTabs.map(([key, label, icon]) => (
            <button key={key} onClick={() => setTab(key)} style={{
              padding:'8px 16px', fontSize:'13px', border:'none',
              cursor:'pointer', borderRadius:'6px', transition:'all 0.15s',
              display:'flex', alignItems:'center', gap:'6px',
              background: tab===key ? 'rgba(59,130,246,0.15)' : 'transparent',
              color: tab===key ? 'var(--blue)' : 'var(--text2)',
              fontWeight: tab===key ? '500' : '400'
            }}>
              <span>{icon}</span>{label}
            </button>
          ))}
        </div>

        {/* Status indicators */}
        <div style={{marginLeft:'auto', display:'flex', alignItems:'center', gap:'12px'}}>

          {/* API key badges */}
          {status && (
            <div style={{display:'flex', gap:'6px'}}>
              {[
                ['AbuseIPDB', status.abuseipdb],
                ['VT',        status.virustotal],
                ['URLScan',   status.urlscan],
              ].map(([name, ok]) => (
                <span key={name} style={{
                  fontSize:'10px', padding:'2px 7px', borderRadius:'4px',
                  background: ok
                    ? 'rgba(16,185,129,0.1)'
                    : 'rgba(239,68,68,0.1)',
                  color: ok ? '#6ee7b7' : '#fca5a5',
                  border: `1px solid ${ok
                    ? 'rgba(16,185,129,0.2)'
                    : 'rgba(239,68,68,0.2)'}`
                }}>{name}</span>
              ))}
            </div>
          )}

          {/* LLM provider pill */}
          <div style={{
            display:'flex', alignItems:'center', gap:'6px',
            padding:'4px 10px', borderRadius:'6px',
            background: status?.provider_ok
              ? 'rgba(16,185,129,0.08)'
              : 'rgba(239,68,68,0.08)',
            border: `1px solid ${status?.provider_ok
              ? 'rgba(16,185,129,0.2)'
              : 'rgba(239,68,68,0.2)'}`
          }}>
            <div style={{
              width:'5px', height:'5px', borderRadius:'50%',
              background: status?.provider_ok ? 'var(--green)' : '#ef4444',
              boxShadow: status?.provider_ok
                ? '0 0 6px #10b981'
                : '0 0 6px #ef4444'
            }}/>
            <span style={{fontSize:'11px',
              color: status?.provider_ok ? 'var(--green)' : '#fca5a5'}}>
              {status
                ? `${status.provider} · ${status.model}`
                : 'connecting...'}
            </span>
          </div>

          {/* Error message if provider is down */}
          {status && !status.provider_ok && status.error && (
            <span style={{
              fontSize:'11px', color:'#fca5a5',
              maxWidth:'200px', lineHeight:'1.4'
            }}>
              ⚠ {status.error}
            </span>
          )}

        </div>
      </nav>
      {/* End nav */}

      {/* Main content */}
      <div style={{maxWidth:'1140px', margin:'0 auto', padding:'36px 24px'}}>

        {/* Evidence Analysis tab */}
        {tab === 'evidence' && (
          <>
            <div style={{marginBottom:'32px'}}>
              <h1 style={{
                fontSize:'28px', fontWeight:'700', color:'var(--text1)',
                letterSpacing:'-0.04em', marginBottom:'8px'
              }}>
                Evidence Analysis
              </h1>
              <p style={{fontSize:'13px', color:'var(--text2)', lineHeight:'1.6'}}>
                Upload an email, log file, or paste text — the agent automatically
                extracts IPs, domains, checks threat intel, and delivers a
                full FP/TP verdict.
              </p>
            </div>

            <FileUpload
              onAnalyze={handleAnalyze}
              loading={loading}
              progress={progress}
            />

            {error && (
              <div style={{
                marginTop:'16px', padding:'14px 16px',
                background:'rgba(239,68,68,0.08)',
                border:'1px solid rgba(239,68,68,0.3)',
                borderRadius:'10px', color:'#fca5a5', fontSize:'13px'
              }}>
                {error}
              </div>
            )}

            {result && <ResultsView data={result} />}
          </>
        )}

        {/* Threat Intel tab */}
        {tab === 'threat' && <ThreatChecker />}

        {/* URL Sandbox tab */}
        {tab === 'sandbox' && (
          <>
            <div style={{marginBottom:'32px'}}>
              <h1 style={{
                fontSize:'28px', fontWeight:'700', color:'var(--text1)',
                letterSpacing:'-0.04em', marginBottom:'8px'
              }}>
                URL Sandbox
              </h1>
              <p style={{fontSize:'13px', color:'var(--text2)', lineHeight:'1.6'}}>
                Submit any URL to URLScan.io for live sandbox analysis —
                get screenshot, server info, malicious verdict, and full
                behavior report.
              </p>
            </div>
            <SandboxView standalone />
          </>
        )}

      </div>
    </div>
  )
}