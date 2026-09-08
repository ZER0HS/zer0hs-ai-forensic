export default function AnomalyList({ anomalies }) {
  const colors = {
    high:   { border:'#ef4444', bg:'#450a0a', badge:'#7f1d1d', text:'#fca5a5' },
    medium: { border:'#f59e0b', bg:'#451a03', badge:'#78350f', text:'#fcd34d' },
    low:    { border:'#3b82f6', bg:'#1e3a5f', badge:'#1e3a8a', text:'#93c5fd' },
  }

  if (!anomalies?.length) return (
    <p style={{fontSize:'13px', color:'#475569'}}>No anomalies detected.</p>
  )

  return (
    <div style={{display:'flex', flexDirection:'column', gap:'10px'}}>
      {anomalies.map((a, i) => {
        const c = colors[a.severity] || colors.low
        return (
          <div key={i} style={{borderLeft:`3px solid ${c.border}`, background: c.bg,
            borderRadius:'0 8px 8px 0', padding:'12px 16px'}}>
            <div style={{display:'flex', alignItems:'center', gap:'8px', marginBottom:'4px'}}>
              <span style={{fontSize:'13px', fontWeight:'500', color:'#f1f5f9'}}>{a.title}</span>
              <span style={{fontSize:'10px', padding:'2px 6px', borderRadius:'3px',
                background: c.badge, color: c.text}}>{a.severity}</span>
            </div>
            <p style={{fontSize:'12px', color:'#94a3b8', lineHeight:'1.5'}}>{a.description}</p>
          </div>
        )
      })}
    </div>
  )
}