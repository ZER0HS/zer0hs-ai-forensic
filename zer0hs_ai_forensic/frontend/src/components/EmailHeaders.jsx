import { severityConfig } from './ui/severity'

const AUTH_COLOR = {
  pass: severityConfig('clean').accent,
  fail: severityConfig('critical').accent,
  softfail: severityConfig('critical').accent,
}

const authColor = v => AUTH_COLOR[v] || '#64748b'
const sevColor  = s => severityConfig(s).accent

export default function EmailHeaders({ data }) {
  if (!data) return (
    <div style={{padding:'20px', textAlign:'center'}}>
      <p style={{fontSize:'13px', color:'var(--text3)'}}>
        Upload a .eml file to see header analysis
      </p>
    </div>
  )

  return (
    <div style={{display:'flex', flexDirection:'column', gap:'14px'}}>

      {/* Auth results */}
      <div style={{background:'var(--bg1)', borderRadius:'12px',
        padding:'18px', border:'1px solid var(--border)'}}>
        <p style={{fontSize:'11px', color:'var(--text3)', marginBottom:'14px',
          textTransform:'uppercase', letterSpacing:'0.06em'}}>Email authentication</p>
        <div style={{display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:'10px'}}>
          {[['SPF', data.auth_results?.spf],
            ['DKIM', data.auth_results?.dkim],
            ['DMARC', data.auth_results?.dmarc]].map(([label, val]) => (
            <div key={label} style={{
              background:'var(--bg2)', borderRadius:'10px', padding:'14px',
              border:`1px solid ${authColor(val)}33`, textAlign:'center'
            }}>
              <p style={{fontSize:'11px', color:'var(--text3)', marginBottom:'6px'}}>{label}</p>
              <p style={{fontSize:'18px', fontWeight:'700', color: authColor(val),
                textTransform:'uppercase'}}>{val || 'unknown'}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Header anomalies */}
      {data.anomalies?.length > 0 && (
        <div style={{background:'var(--bg1)', borderRadius:'12px',
          padding:'18px', border:'1px solid var(--border)'}}>
          <p style={{fontSize:'11px', color:'var(--text3)', marginBottom:'12px',
            textTransform:'uppercase', letterSpacing:'0.06em'}}>
            Header anomalies ({data.anomalies.length})
          </p>
          {data.anomalies.map((a,i) => (
            <div key={i} style={{
              display:'flex', gap:'10px', padding:'10px 12px',
              marginBottom:'8px', borderRadius:'8px',
              background:`${sevColor(a.severity)}11`,
              border:`1px solid ${sevColor(a.severity)}33`
            }}>
              <span style={{fontSize:'10px', padding:'2px 8px', borderRadius:'4px',
                background:`${sevColor(a.severity)}22`,
                color: sevColor(a.severity), flexShrink:0, alignSelf:'flex-start',
                marginTop:'1px', textTransform:'uppercase'}}>
                {a.severity}
              </span>
              <div>
                <p style={{fontSize:'12px', fontWeight:'500',
                  color:'var(--text1)', marginBottom:'2px'}}>
                  {a.type.replace(/_/g,' ')}
                </p>
                <p style={{fontSize:'12px', color:'var(--text2)'}}>{a.detail}</p>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Routing chain */}
      {data.received_chain?.length > 0 && (
        <div style={{background:'var(--bg1)', borderRadius:'12px',
          padding:'18px', border:'1px solid var(--border)'}}>
          <p style={{fontSize:'11px', color:'var(--text3)', marginBottom:'14px',
            textTransform:'uppercase', letterSpacing:'0.06em'}}>
            Email routing chain ({data.received_chain.length} hops)
          </p>
          <div style={{position:'relative', paddingLeft:'24px'}}>
            <div style={{position:'absolute', left:'8px', top:0, bottom:0,
              width:'1px', background:'var(--border2)'}}/>
            {data.received_chain.map((hop,i) => (
              <div key={i} style={{position:'relative', marginBottom:'14px'}}>
                <div style={{position:'absolute', left:'-20px', top:'4px',
                  width:'10px', height:'10px', borderRadius:'50%',
                  background: i===0 ? 'var(--green)' :
                    i===data.received_chain.length-1 ? 'var(--blue)' : 'var(--border2)',
                  border:'2px solid var(--bg1)'}}/>
                <div style={{display:'flex', gap:'8px', flexWrap:'wrap'}}>
                  {hop.ip && (
                    <span style={{fontSize:'11px', padding:'2px 8px', borderRadius:'5px',
                      background:'rgba(59,130,246,0.1)', color:'#93c5fd',
                      fontFamily:'monospace'}}>{hop.ip}</span>
                  )}
                  {hop.from && (
                    <span style={{fontSize:'11px', color:'var(--text2)'}}>
                      from <span style={{color:'var(--text1)'}}>{hop.from}</span>
                    </span>
                  )}
                  {hop.by && (
                    <span style={{fontSize:'11px', color:'var(--text3)'}}>
                      → {hop.by}
                    </span>
                  )}
                </div>
                {hop.time && (
                  <p style={{fontSize:'10px', color:'var(--text3)',
                    marginTop:'3px', fontFamily:'monospace'}}>{hop.time}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Basic headers */}
      <div style={{background:'var(--bg1)', borderRadius:'12px',
        padding:'18px', border:'1px solid var(--border)'}}>
        <p style={{fontSize:'11px', color:'var(--text3)', marginBottom:'12px',
          textTransform:'uppercase', letterSpacing:'0.06em'}}>Header fields</p>
        {[
          ['From',       data.from],
          ['To',         data.to],
          ['Subject',    data.subject],
          ['Date',       data.date],
          ['Reply-To',   data.reply_to],
          ['Message-ID', data.message_id],
          ['Routing IPs',data.routing_ips?.join(', ')],
        ].filter(([,v])=>v).map(([label,val])=>(
          <div key={label} style={{display:'flex', gap:'12px', padding:'8px 0',
            borderBottom:'1px solid var(--border)', fontSize:'12px'}}>
            <span style={{color:'var(--text3)', minWidth:'90px', flexShrink:0}}>{label}</span>
            <span style={{color:'var(--text1)', fontFamily:'monospace',
              wordBreak:'break-all'}}>{val}</span>
          </div>
        ))}
      </div>

      {/* Attachments */}
      {data.attachments?.length > 0 && (
        <div style={{background:'var(--bg1)', borderRadius:'12px',
          padding:'18px', border:'1px solid var(--border)'}}>
          <p style={{fontSize:'11px', color:'var(--text3)', marginBottom:'12px',
            textTransform:'uppercase', letterSpacing:'0.06em'}}>
            Attachments ({data.attachments.length})
          </p>
          {data.attachments.map((att,i) => (
            <div key={i} style={{padding:'12px', background:'var(--bg2)',
              borderRadius:'8px', marginBottom:'8px', border:'1px solid var(--border)'}}>
              <p style={{fontSize:'13px', fontWeight:'500',
                color:'var(--text1)', marginBottom:'6px'}}>{att.filename}</p>
              <div style={{display:'flex', gap:'8px', flexWrap:'wrap'}}>
                <Tag label="Type"   val={att.content_type} />
                <Tag label="Size"   val={`${att.size_bytes} bytes`} />
                <Tag label="MD5"    val={att.md5?.slice(0,16)+'...'} mono />
                <Tag label="SHA256" val={att.sha256?.slice(0,16)+'...'} mono />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function Tag({ label, val, mono }) {
  return (
    <span style={{fontSize:'11px', padding:'3px 8px', borderRadius:'5px',
      background:'var(--bg3)', color:'var(--text2)', border:'1px solid var(--border)',
      fontFamily: mono ? 'monospace' : 'inherit'}}>
      <span style={{color:'var(--text3)'}}>{label}: </span>{val}
    </span>
  )
}