import { useState } from 'react'
import { apiClient } from '../api'
import VerdictBanner from './VerdictBanner'
import { scoreToSeverity, severityConfig } from './ui/severity'

const scoreColor = s => severityConfig(scoreToSeverity(s)).accent

export default function ThreatChecker() {
  const [indicator, setIndicator] = useState('')
  const [context, setContext]     = useState('')
  const [result, setResult]       = useState(null)
  const [loading, setLoading]     = useState(false)
  const [error, setError]         = useState(null)

  async function check() {
    if (!indicator.trim()) return
    setLoading(true); setError(null); setResult(null)
    try {
      const form = new FormData()
      form.append('indicator', indicator.trim())
      form.append('context', context)
      const { data } = await apiClient.post('/threat-check', form)
      setResult(data)
    } catch(e) { setError('Check failed — make sure backend is running') }
    setLoading(false)
  }

  const intel = result?.threat_intel
  const verdict = result?.ai_verdict

  return (
    <div>
      <div style={{marginBottom:'32px'}}>
        <h1 style={{fontSize:'28px', fontWeight:'700', color:'var(--text1)',
          letterSpacing:'-0.04em', marginBottom:'8px'}}>Threat Intelligence</h1>
        <p style={{fontSize:'13px', color:'var(--text2)'}}>
          Check a single IP or domain against AbuseIPDB + VirusTotal with AI FP/TP scoring
        </p>
      </div>

      <div style={{background:'var(--bg2)', border:'1px solid var(--border)',
        borderRadius:'16px', padding:'24px', marginBottom:'24px'}}>
        <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:'14px', marginBottom:'14px'}}>
          <div>
            <label style={{fontSize:'11px', color:'var(--text3)', display:'block',
              marginBottom:'7px', textTransform:'uppercase', letterSpacing:'0.06em'}}>
              IP address or domain
            </label>
            <input value={indicator} onChange={e => setIndicator(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && check()}
              placeholder="192.168.1.1 or malicious.com"
              style={{width:'100%', padding:'11px 14px', background:'var(--bg1)',
                border:'1px solid var(--border)', borderRadius:'10px', color:'var(--text1)',
                fontSize:'13px', outline:'none', fontFamily:'monospace'}} />
          </div>
          <div>
            <label style={{fontSize:'11px', color:'var(--text3)', display:'block',
              marginBottom:'7px', textTransform:'uppercase', letterSpacing:'0.06em'}}>
              Context (optional)
            </label>
            <input value={context} onChange={e => setContext(e.target.value)}
              placeholder="e.g. found in phishing email header"
              style={{width:'100%', padding:'11px 14px', background:'var(--bg1)',
                border:'1px solid var(--border)', borderRadius:'10px', color:'var(--text1)',
                fontSize:'13px', outline:'none'}} />
          </div>
        </div>
        <button onClick={check} disabled={loading || !indicator.trim()} style={{
          padding:'11px 28px',
          background: loading ? 'var(--bg4)' : 'linear-gradient(135deg, #7c3aed, #6366f1)',
          color:'white', border:'none', borderRadius:'10px',
          fontSize:'13px', fontWeight:'600', cursor: loading ? 'not-allowed' : 'pointer'
        }}>
          {loading ? 'Checking...' : 'Check Indicator'}
        </button>
      </div>

      {error && <div style={{padding:'12px 16px', background:'rgba(239,68,68,0.08)',
        border:'1px solid rgba(239,68,68,0.3)', borderRadius:'10px',
        color:'#fca5a5', fontSize:'13px', marginBottom:'16px'}}>{error}</div>}

      {result && verdict && (
        <>
          <VerdictBanner verdict={{
            ...verdict,
            case_summary: verdict.reasoning,
            severity_breakdown: null,
            mitre_techniques: verdict.mitre_technique ? [verdict.mitre_technique] : []
          }} />

          {intel && (
            <div style={{background:'var(--bg2)', border:'1px solid var(--border)',
              borderRadius:'16px', padding:'20px', marginTop:'16px'}}>
              <p style={{fontSize:'11px', color:'var(--text3)', marginBottom:'14px',
                textTransform:'uppercase', letterSpacing:'0.06em'}}>Threat intel — {intel.source}</p>
              <div style={{display:'flex', alignItems:'center', gap:'16px', marginBottom:'16px'}}>
                <div style={{fontSize:'40px', fontWeight:'800',
                  color: scoreColor(intel.abuse_score||0)}}>{intel.abuse_score||0}</div>
                <div style={{flex:1}}>
                  <div style={{height:'6px', background:'var(--bg4)', borderRadius:'3px'}}>
                    <div style={{width:`${intel.abuse_score||0}%`, height:'100%',
                      background: scoreColor(intel.abuse_score||0), borderRadius:'3px',
                      transition:'width 0.8s ease'}}/>
                  </div>
                  <p style={{fontSize:'11px', color:'var(--text3)', marginTop:'4px'}}>abuse confidence score</p>
                </div>
              </div>
              <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:'8px'}}>
                {[
                  ['Country', intel.country],
                  ['ISP', intel.isp],
                  ['Usage type', intel.usage_type],
                  ['Total reports', intel.total_reports],
                  ['Malicious votes', intel.malicious_votes],
                  ['Total scanners', intel.total_scanners],
                ].filter(([,v]) => v !== undefined && v !== null).map(([label, val]) => (
                  <div key={label} style={{display:'flex', justifyContent:'space-between',
                    padding:'8px 12px', background:'var(--bg1)', borderRadius:'8px',
                    border:'1px solid var(--border)', fontSize:'12px'}}>
                    <span style={{color:'var(--text3)'}}>{label}</span>
                    <span style={{color:'var(--text1)', fontFamily:'monospace'}}>{val}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}