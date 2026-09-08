// SECURITY: this component used to render the LLM's excerpt via
// `dangerouslySetInnerHTML` because the backend asked the model for
// "HTML spans" — a real XSS vector, since the excerpt is built from the
// attacker's own email text. The backend now returns plain text plus
// numeric offsets (see agent.py / schemas.py), and everything below is
// rendered as ordinary React text nodes (auto-escaped) — no HTML from the
// model ever reaches the DOM.
export default function EntityView({ data, highlight }) {
  const colors = {
    persons: ['#1e3a5f','#60a5fa'],
    places:  ['#14532d','#4ade80'],
    times:   ['#451a03','#fb923c'],
    orgs:    ['#3b0764','#c084fc'],
  }
  const labels = { persons:'People', places:'Places', times:'Times', orgs:'Orgs / Systems' }

  return (
    <div>
      <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:'12px', marginBottom:'16px'}}>
        {Object.entries(data||{}).map(([type, items]) => (
          <div key={type} style={{background:'#0f1117', borderRadius:'8px', padding:'16px'}}>
            <p style={{fontSize:'11px', color:'#64748b', marginBottom:'10px', textTransform:'uppercase'}}>{labels[type]}</p>
            <div style={{display:'flex', flexWrap:'wrap', gap:'6px'}}>
              {(items||[]).map(name => (
                <span key={name} style={{fontSize:'12px', padding:'3px 10px', borderRadius:'4px',
                  background: colors[type]?.[0], color: colors[type]?.[1], border:`1px solid ${colors[type]?.[1]}33`}}>
                  {name}
                </span>
              ))}
              {(!items||items.length===0) && <span style={{fontSize:'12px', color:'#475569'}}>None found</span>}
            </div>
          </div>
        ))}
      </div>
      {highlight?.text && (
        <div style={{background:'#0f1117', borderRadius:'8px', padding:'16px'}}>
          <p style={{fontSize:'11px', color:'#64748b', marginBottom:'10px', textTransform:'uppercase'}}>Highlighted evidence</p>
          <p style={{fontSize:'13px', lineHeight:'1.8', color:'#cbd5e1', whiteSpace:'pre-wrap'}}>
            <HighlightedExcerpt text={highlight.text} start={highlight.start} end={highlight.end} />
          </p>
        </div>
      )}
    </div>
  )
}

// Slices plain text into [prefix, marked span, suffix] and renders each as
// a plain React text node — a <mark> around one substring, never raw HTML.
function HighlightedExcerpt({ text, start, end }) {
  const validRange = Number.isInteger(start) && Number.isInteger(end) &&
    start >= 0 && end > start && end <= text.length

  if (!validRange) return <>{text}</>

  return (
    <>
      {text.slice(0, start)}
      <mark style={{background:'rgba(245,158,11,0.35)', color:'inherit', borderRadius:'3px', padding:'0 2px'}}>
        {text.slice(start, end)}
      </mark>
      {text.slice(end)}
    </>
  )
}
