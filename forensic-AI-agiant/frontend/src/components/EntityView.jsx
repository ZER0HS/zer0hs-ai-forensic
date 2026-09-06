export default function EntityView({ data, highlighted }) {
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
      {highlighted && (
        <div style={{background:'#0f1117', borderRadius:'8px', padding:'16px'}}>
          <p style={{fontSize:'11px', color:'#64748b', marginBottom:'10px', textTransform:'uppercase'}}>Highlighted evidence</p>
          <div style={{fontSize:'13px', lineHeight:'1.8', color:'#cbd5e1'}}
            dangerouslySetInnerHTML={{__html: highlighted}} />
        </div>
      )}
    </div>
  )
}