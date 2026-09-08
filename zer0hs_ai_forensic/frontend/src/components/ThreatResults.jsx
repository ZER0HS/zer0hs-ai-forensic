export default function ThreatResults({ results, indicators }) {
  if (!results?.length) return (
    <p style={{fontSize:'13px', color:'var(--text3)'}}>No indicators extracted from evidence.</p>
  )

  const scoreColor = s =>
    s >= 75 ? '#ef4444' : s >= 40 ? '#f97316' : s >= 15 ? '#f59e0b' : '#10b981'

  return (
    <div>
      {indicators?.private_ips?.length > 0 && (
        <div style={{
          padding:'10px 14px', background:'rgba(59,130,246,0.06)',
          border:'1px solid rgba(59,130,246,0.2)', borderRadius:'8px',
          fontSize:'12px', color:'var(--text2)', marginBottom:'16px'
        }}>
          Private IPs found (not checked): {indicators.private_ips.join(', ')}
        </div>
      )}

      <div style={{display:'flex', flexDirection:'column', gap:'10px'}}>
        {results.map((r, i) => (
          <div key={i} style={{
            background:'var(--bg1)', border:'1px solid var(--border)',
            borderRadius:'12px', padding:'16px',
            borderLeft:`3px solid ${scoreColor(r.abuse_score || 0)}`
          }}>
            <div style={{display:'flex', alignItems:'center', gap:'12px', marginBottom:'10px'}}>
              <span style={{
                fontSize:'11px', padding:'2px 8px', borderRadius:'4px',
                background:'var(--bg3)', color:'var(--text2)',
                textTransform:'uppercase', letterSpacing:'0.05em'
              }}>{r.type}</span>
              <span style={{fontSize:'13px', fontWeight:'600', color:'var(--text1)', fontFamily:'monospace'}}>
                {r.value}
              </span>
              <span style={{marginLeft:'auto', fontSize:'11px', color:'var(--text3)'}}>
                via {r.source}
              </span>
              {/* Score gauge */}
              <div style={{display:'flex', alignItems:'center', gap:'8px'}}>
                <div style={{width:'80px', height:'4px', background:'var(--bg4)', borderRadius:'2px'}}>
                  <div style={{
                    width:`${r.abuse_score||0}%`, height:'100%',
                    background: scoreColor(r.abuse_score||0), borderRadius:'2px'
                  }}/>
                </div>
                <span style={{fontSize:'12px', fontWeight:'700', color: scoreColor(r.abuse_score||0), minWidth:'28px'}}>
                  {r.abuse_score||0}
                </span>
              </div>
            </div>

            <div style={{display:'flex', flexWrap:'wrap', gap:'8px'}}>
              {r.country      && <Tag label="Country"  value={r.country} />}
              {r.isp          && <Tag label="ISP"      value={r.isp} />}
              {r.usage_type   && <Tag label="Type"     value={r.usage_type} />}
              {r.total_reports!== undefined && <Tag label="Reports" value={r.total_reports} />}
              {r.malicious_votes !== undefined && <Tag label="Malicious" value={`${r.malicious_votes}/${r.total_scanners}`} />}
              {r.error        && <Tag label="Error"    value={r.error} warn />}
              {r.note         && <Tag label="Note"     value={r.note} />}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function Tag({ label, value, warn }) {
  return (
    <div style={{
      fontSize:'11px', padding:'4px 10px', borderRadius:'6px',
      background: warn ? 'rgba(239,68,68,0.1)' : 'var(--bg3)',
      color: warn ? '#fca5a5' : 'var(--text2)',
      border:`1px solid ${warn ? 'rgba(239,68,68,0.3)' : 'var(--border)'}`
    }}>
      <span style={{color:'var(--text3)'}}>{label}: </span>{value}
    </div>
  )
}