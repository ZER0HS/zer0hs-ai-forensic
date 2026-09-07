import { useState } from 'react'
import { AlertTriangle, Camera, CircleCheck, Globe, Loader2, Package, ScanSearch, ShieldAlert } from 'lucide-react'
import { apiClient } from '../api'

export default function SandboxView({ urls, standalone }) {
  const [results, setResults] = useState({})
  const [loading, setLoading] = useState({})
  const [custom, setCustom]   = useState('')

  async function scan(url) {
    const key = url
    setLoading(p => ({...p, [key]: true}))
    try {
      const form = new FormData()
      form.append('url', url)
      const { data } = await apiClient.post('/sandbox', form)
      setResults(p => ({...p, [key]: data}))
    } catch(e) {
      setResults(p => ({...p, [key]: {error: 'Scan failed — check backend', status:'error'}}))
    }
    setLoading(p => ({...p, [key]: false}))
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
          URL to sandbox
        </label>
        <div style={{display:'flex', gap:'10px'}}>
          <input
            value={custom}
            onChange={e => setCustom(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && custom && scan(custom)}
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
          <button
            onClick={() => custom.trim() && scan(custom.trim())}
            disabled={!custom.trim() || loading[custom]}
            style={{
              padding:'12px 24px',
              background: loading[custom]
                ? 'var(--bg4)'
                : 'linear-gradient(135deg, #7c3aed, #6366f1)',
              color:'white', border:'none', borderRadius:'10px',
              fontSize:'13px', fontWeight:'600',
              cursor: loading[custom] ? 'not-allowed' : 'pointer',
              flexShrink:0, transition:'opacity 0.15s',
              opacity: !custom.trim() ? 0.5 : 1
            }}>
            {loading[custom] ? 'Scanning...' : 'Submit to Sandbox'}
          </button>
        </div>

        {/* Info row */}
        <div style={{display:'flex', gap:'20px', marginTop:'12px', flexWrap:'wrap'}}>
          {[
            [Globe, 'Powered by URLScan.io'],
            [Camera, 'Full page screenshot'],
            [ScanSearch, 'Behavior analysis'],
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
          <SandboxCard url={custom} result={results[custom]} />
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
                  <button
                    type="button"
                    onClick={() => scan(url)}
                    disabled={loading[url]}
                    style={{
                      display:'flex', alignItems:'center', gap:'5px',
                      padding:'7px 16px', flexShrink:0,
                      background: loading[url] ? 'var(--bg4)' : 'var(--bg3)',
                      color: loading[url] ? 'var(--text3)' : 'var(--text2)',
                      border:'1px solid var(--border)', borderRadius:'8px',
                      fontSize:'12px', cursor: loading[url] ? 'wait' : 'pointer'
                    }}>
                    {loading[url]
                      ? <><Loader2 size={12} style={{animation:'spin 0.8s linear infinite'}} /> Scanning...</>
                      : <><Package size={12} /> Sandbox</>}
                  </button>
                </div>
                {results[url] && <SandboxCard url={url} result={results[url]} inline />}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function SandboxCard({ url, result: r, inline }) {
  if (r.status === 'error') return (
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
          <span style={{fontSize:'12px', color:'var(--text3)'}}>Risk score</span>
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