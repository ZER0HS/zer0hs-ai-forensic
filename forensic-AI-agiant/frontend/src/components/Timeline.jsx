export default function Timeline({ events }) {
  if (!events?.length) return <p style={{fontSize:'13px', color:'var(--text3)'}}>No timeline events found.</p>

  return (
    <div style={{position:'relative', paddingLeft:'28px'}}>
      <div style={{position:'absolute', left:'9px', top:'12px', bottom:'12px',
        width:'1px', background:'var(--border2)'}} />
      {events.map((e, i) => (
        <div key={i} style={{position:'relative', marginBottom:'22px'}}>
          <div style={{
            position:'absolute', left:'-22px', top:'4px',
            width:'12px', height:'12px', borderRadius:'50%',
            border:'2px solid var(--bg2)',
            background: e.anomaly ? '#ef4444' : 'var(--blue)',
            boxShadow: e.anomaly ? '0 0 8px rgba(239,68,68,0.5)' : '0 0 8px rgba(59,130,246,0.4)'
          }} />
          <p style={{fontSize:'11px', color:'var(--text3)', marginBottom:'3px', fontFamily:'monospace'}}>{e.time}</p>
          <p style={{fontSize:'13px', color:'var(--text1)', lineHeight:'1.6'}}>{e.event}</p>
          {e.actors && (
            <p style={{fontSize:'11px', color:'var(--text3)', marginTop:'4px'}}>
              <span style={{color:'var(--text3)'}}>actor: </span>
              <span style={{color:'var(--text2)'}}>{e.actors}</span>
            </p>
          )}
          {e.anomaly && (
            <span style={{fontSize:'10px', padding:'2px 8px', marginTop:'6px', display:'inline-block',
              background:'rgba(239,68,68,0.1)', color:'#fca5a5',
              border:'1px solid rgba(239,68,68,0.3)', borderRadius:'4px'}}>
              ⚠ anomaly flagged
            </span>
          )}
        </div>
      ))}
    </div>
  )
}