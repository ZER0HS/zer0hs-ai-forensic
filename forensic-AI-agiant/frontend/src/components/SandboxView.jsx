import { useState } from 'react'
import { AlertTriangle, Camera, CircleCheck, Globe, Loader2, Package, Search, ShieldAlert } from 'lucide-react'
import { apiClient } from '../api'
import SeverityBadge from './ui/SeverityBadge'

export default function SandboxView({ urls, standalone }) {
  // Keyed by URL: { check: <sandbox/check response>, scan: <sandbox/scan response> }
  const [results, setResults]     = useState({})
  const [checking, setChecking]   = useState({})
  const [scanning, setScanning]   = useState({})
  const [custom, setCustom]       = useState('')

  async function runCheck(url) {
    setChecking(p => ({...p, [url]: true}))
    try {
      const form = new FormData()
      form.append('url', url)
      const { data } = await apiClient.post('/sandbox/check', form)
      setResults(p => ({...p, [url]: {...p[url], check: data}}))
    } catch {
      setResults(p => ({...p, [url]: {...p[url], check: {error: 'Check failed — check backend'}}}))
    }
    setChecking(p => ({...p, [url]: false}))
  }

  async function runScan(url) {
    setScanning(p => ({...p, [url]: true}))
    try {
      const form = new FormData()
      form.append('url', url)
      const { data } = await apiClient.post('/sandbox/scan', form)
      // The scan response already carries the same verdict Check would
      // produce (computed concurrently server-side), so this always
      // fills in `check` too even if Check was never run separately.
      setResults(p => ({...p, [url]: {...p[url], scan: data, check: data.check || p[url]?.check}}))
    } catch {
      setResults(p => ({...p, [url]: {...p[url], scan: {error: 'Scan failed — check backend', status: 'error'}}}))
    }
    setScanning(p => ({...p, [url]: false}))
  }

  return (
    <div>
      {/* Input box — bigger in standalone mode */}
      <div style={{
        background:'var(--bg2)', border:'1px solid var(--border)',
        borderRadius:'16px', padding:'24px', marginBottom:'20px'
      }}>
        <label style={{fontSize:'11px', color:'var(--text3)', display:'block',
          marginBottom:'10px', textTransform:'uppercase', letterSpacing:'0.06em'}}>
          URL to check or sandbox
        </label>
        <div style={{display:'flex', gap:'10px'}}>
          <input
            value={custom}
            onChange={e => setCustom(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && custom && runCheck(custom)}
            placeholder="https://suspicious-site.com/path?id=abc"
            style={{
              flex:1, padding:'12px 16px',
              background:'var(--bg1)', border:'1px solid var(--border)',
              borderRadius:'10px', color:'var(--text1)',
              fontSize:'13px', outline:'none', fontFamily:'monospace',
              transition:'border-color 0.15s'
            }}
            onFocus={e => e.target.style.borderColor = 'var(--border2)'}
            onBlur={e  => e.target.style.borderColor = 'var(--border)'}
          />
          <ActionButton
            label="Check" loadingLabel="Checking..." icon={Search}
            loading={checking[custom]} disabled={!custom.trim() || checking[custom]}
            variant="primary"
            onClick={() => custom.trim() && runCheck(custom.trim())}
          />
          <ActionButton
            label="Scan" loadingLabel="Scanning..." icon={Package}
            loading={scanning[custom]} disabled={!custom.trim() || scanning[custom]}
            variant="secondary"
            onClick={() => custom.trim() && runScan(custom.trim())}
          />
        </div>

        {/* Info row */}
        <div style={{display:'flex', gap:'20px', marginTop:'12px', flexWrap:'wrap'}}>
          {[
            [Search, 'Check: threat intel + rule engine, seconds'],
            [Globe, 'Scan: URLScan.io, 15-45s, screenshot + behavior'],
            [Camera, 'Scan includes the same verdict as Check'],
            [AlertTriangle, 'Do not submit URLs with passwords or PII'],
          ].map(([Icon, text]) => (
            <span key={text} style={{fontSize:'11px', color:'var(--text3)',
              display:'flex', alignItems:'center', gap:'5px'}}>
              <Icon size={12} /> {text}
            </span>
          ))}
        </div>
      </div>

      {/* Result for manually entered URL */}
      {custom && results[custom] && (
        <div style={{marginBottom:'20px'}}>
          <UrlResultCard url={custom} entry={results[custom]} />
        </div>
      )}

      {/* Auto-detected URLs from evidence */}
      {urls?.length > 0 && (
        <div>
          <p style={{fontSize:'11px', color:'var(--text3)', marginBottom:'12px',
            textTransform:'uppercase', letterSpacing:'0.06em'}}>
            URLs extracted from evidence ({urls.length})
          </p>
          <div style={{display:'flex', flexDirection:'column', gap:'10px'}}>
            {urls.map(url => (
              <div key={url} style={{
                background:'var(--bg2)', border:'1px solid var(--border)',
                borderRadius:'12px', padding:'16px'
              }}>
                <div style={{display:'flex', alignItems:'center', gap:'10px', marginBottom: results[url] ? '14px' : 0}}>
                  <span style={{fontSize:'12px', color:'var(--text2)',
                    fontFamily:'monospace', flex:1, wordBreak:'break-all'}}>{url}</span>
                  <ActionButton
                    label="Check" loadingLabel="Checking..." icon={Search} compact
                    loading={checking[url]} disabled={checking[url]}
                    variant="secondary" onClick={() => runCheck(url)}
                  />
                  <ActionButton
                    label="Scan" loadingLabel="Scanning..." icon={Package} compact
                    loading={scanning[url]} disabled={scanning[url]}
                    variant="secondary" onClick={() => runScan(url)}
                  />
                </div>
                {results[url] && <UrlResultCard url={url} entry={results[url]} inline />}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function ActionButton({ label, loadingLabel, icon: Icon, loading, disabled, variant, compact, onClick }) {
  const primary = variant === 'primary'
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      style={{
        display:'flex', alignItems:'center', gap:'5px', flexShrink:0,
        padding: compact ? '7px 14px' : '12px 20px',
        background: disabled
          ? 'var(--bg4)'
          : primary ? 'linear-gradient(135deg, #3b82f6, #6366f1)' : 'var(--bg3)',
        color: primary ? 'white' : (disabled ? 'var(--text3)' : 'var(--text2)'),
        border: primary ? 'none' : '1px solid var(--border)',
        borderRadius: compact ? '8px' : '10px',
        fontSize: compact ? '12px' : '13px', fontWeight: primary ? '600' : '500',
        cursor: disabled ? 'not-allowed' : 'pointer', transition:'opacity 0.15s',
      }}>
      {loading
        ? <><Loader2 size={compact ? 12 : 14} style={{animation:'spin 0.8s linear infinite'}} /> {loadingLabel}</>
        : <><Icon size={compact ? 12 : 14} /> {label}</>}
    </button>
  )
}

// Combines the Check verdict and the Scan (URLScan) result into one view.
// Either can be present alone (Check run without a Scan, or vice versa
// since Scan always fills in `check` too), or both together.
function UrlResultCard({ url, entry, inline }) {
  const { check, scan } = entry
  return (
    <div style={{display:'flex', flexDirection:'column', gap:'12px'}}>
      {check && <CheckVerdictCard result={check} />}
      {scan && <ScanDetailsCard result={scan} inline={inline} />}
    </div>
  )
}

function CheckVerdictCard({ result }) {
  if (result.error) return (
    <div style={{display:'flex', alignItems:'center', gap:'6px',
      padding:'10px 14px', background:'rgba(239,68,68,0.08)',
      border:'1px solid rgba(239,68,68,0.2)', borderRadius:'8px',
      fontSize:'12px', color:'#fca5a5'}}>
      <AlertTriangle size={13} /> {result.error}
    </div>
  )

  const v = result.ai_verdict || {}
  const isTP = v.verdict === 'TP'
  const typosquat = result.typosquat

  return (
    <div style={{
      background: isTP ? 'rgba(239,68,68,0.06)' : 'rgba(16,185,129,0.06)',
      border: `1px solid ${isTP ? 'rgba(239,68,68,0.25)' : 'rgba(16,185,129,0.25)'}`,
      borderRadius:'12px', padding:'16px',
    }}>
      <div style={{display:'flex', alignItems:'center', gap:'10px', marginBottom:'10px', flexWrap:'wrap'}}>
        <span style={{fontSize:'18px', fontWeight:'800', color: isTP ? '#fca5a5' : '#6ee7b7'}}>
          {v.verdict}
        </span>
        <SeverityBadge severity={v.risk_level} size="sm" />
        <span style={{fontSize:'12px', color:'var(--text3)'}}>{v.confidence}% confidence</span>
        {typosquat?.detected && (
          <span style={{fontSize:'11px', padding:'2px 8px', borderRadius:'4px',
            background:'rgba(239,68,68,0.15)', color:'#fca5a5', border:'1px solid rgba(239,68,68,0.3)'}}>
            typosquat of {typosquat.brand} ({typosquat.technique})
          </span>
        )}
      </div>
      <p style={{fontSize:'12px', color:'var(--text2)', lineHeight:'1.6', marginBottom: v.recommended_action ? '8px' : 0}}>
        {v.reasoning}
      </p>
      {v.recommended_action && (
        <p style={{fontSize:'12px', color:'var(--text3)'}}>
          <span style={{color:'var(--text2)', fontWeight:'500'}}>Recommended: </span>{v.recommended_action}
        </p>
      )}
    </div>
  )
}

function ScanDetailsCard({ result: r, inline }) {
  if (r.error || r.status === 'error') return (
    <div style={{display:'flex', alignItems:'center', gap:'6px',
      padding:'10px 14px', background:'rgba(239,68,68,0.08)',
      border:'1px solid rgba(239,68,68,0.2)', borderRadius:'8px',
      fontSize:'12px', color:'#fca5a5'}}>
      <AlertTriangle size={13} /> {r.error}
    </div>
  )

  if (r.status === 'pending') return (
    <div style={{padding:'12px 14px', background:'rgba(245,158,11,0.08)',
      border:'1px solid rgba(245,158,11,0.2)', borderRadius:'8px'}}>
      <p style={{display:'flex', alignItems:'center', gap:'6px',
        fontSize:'12px', color:'#fcd34d', marginBottom:'6px'}}>
        <Loader2 size={13} style={{animation:'spin 0.8s linear infinite'}} /> {r.message}
      </p>
      <a href={r.result_url} target="_blank" rel="noreferrer"
        style={{fontSize:'12px', color:'var(--blue)'}}>
        View live results on URLScan.io →
      </a>
    </div>
  )

  const malColor = r.malicious ? '#ef4444' : '#10b981'
  const malBg    = r.malicious ? 'rgba(239,68,68,0.1)' : 'rgba(16,185,129,0.1)'

  return (
    <div style={{
      background: inline ? 'var(--bg1)' : 'var(--bg2)',
      border:'1px solid var(--border)',
      borderRadius:'12px', padding:'18px'
    }}>
      {/* Verdict row */}
      <div style={{display:'flex', alignItems:'center', gap:'12px', marginBottom:'16px', flexWrap:'wrap'}}>
        <span style={{
          display:'flex', alignItems:'center', gap:'6px',
          fontSize:'13px', fontWeight:'700', padding:'5px 14px',
          borderRadius:'20px', background: malBg, color: malColor,
          border:`1px solid ${malColor}44`
        }}>
          {r.malicious ? <><ShieldAlert size={14} /> MALICIOUS</> : <><CircleCheck size={14} /> CLEAN</>}
        </span>

        <div style={{display:'flex', alignItems:'center', gap:'8px'}}>
          <span style={{fontSize:'12px', color:'var(--text3)'}}>URLScan risk score</span>
          <div style={{width:'80px', height:'5px', background:'var(--bg4)', borderRadius:'3px'}}>
            <div style={{
              width:`${Math.min(r.score||0, 100)}%`, height:'100%',
              background: malColor, borderRadius:'3px', transition:'width 0.6s ease'
            }}/>
          </div>
          <span style={{fontSize:'12px', fontWeight:'700', color: malColor}}>{r.score||0}</span>
        </div>

        {r.tags?.map(t => (
          <span key={t} style={{fontSize:'11px', padding:'3px 8px',
            background:'rgba(239,68,68,0.1)', color:'#fca5a5',
            border:'1px solid rgba(239,68,68,0.2)', borderRadius:'4px'}}>{t}</span>
        ))}
      </div>

      {/* Details grid */}
      <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:'8px', marginBottom:'14px'}}>
        {[
          ['Final URL', r.final_url],
          ['Server IP', r.ip],
          ['Country',   r.country],
          ['Server',    r.server],
        ].filter(([,v]) => v).map(([label, val]) => (
          <div key={label} style={{
            padding:'8px 12px', background:'var(--bg3)',
            borderRadius:'8px', border:'1px solid var(--border)', fontSize:'12px'
          }}>
            <span style={{color:'var(--text3)'}}>{label}: </span>
            <span style={{color:'var(--text1)', fontFamily:'monospace',
              wordBreak:'break-all'}}>{val}</span>
          </div>
        ))}
      </div>

      {/* Screenshot preview */}
      {r.screenshot && (
        <div style={{marginBottom:'12px'}}>
          <a href={r.screenshot} target="_blank" rel="noreferrer">
            <img
              src={r.screenshot}
              alt="Page screenshot"
              onError={e => e.target.style.display='none'}
              style={{
                width:'100%', maxHeight:'220px', objectFit:'cover',
                borderRadius:'8px', border:'1px solid var(--border)',
                cursor:'pointer', transition:'opacity 0.2s'
              }}
            />
          </a>
          <p style={{fontSize:'11px', color:'var(--text3)', marginTop:'4px'}}>
            Click screenshot to view full size
          </p>
        </div>
      )}

      {/* Links */}
      <div style={{display:'flex', gap:'12px'}}>
        <a href={r.result_url} target="_blank" rel="noreferrer"
          style={{fontSize:'12px', color:'var(--blue)', textDecoration:'none',
            padding:'6px 12px', background:'rgba(59,130,246,0.1)',
            border:'1px solid rgba(59,130,246,0.2)', borderRadius:'6px'}}>
          Full report →
        </a>
        {r.screenshot && (
          <a href={r.screenshot} target="_blank" rel="noreferrer"
            style={{fontSize:'12px', color:'var(--purple)', textDecoration:'none',
              padding:'6px 12px', background:'rgba(139,92,246,0.1)',
              border:'1px solid rgba(139,92,246,0.2)', borderRadius:'6px'}}>
            Screenshot →
          </a>
        )}
      </div>
    </div>
  )
}
