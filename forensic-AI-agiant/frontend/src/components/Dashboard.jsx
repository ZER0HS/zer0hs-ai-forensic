import { useState } from 'react'
import EntityView from './EntityView'
import AnomalyList from './AnomalyList'
import Timeline from './Timeline'
import ReportExport from './ReportExport'

const tabs = ['Overview', 'Entities', 'Anomalies', 'Timeline', 'Report']

export default function Dashboard({ data }) {
  const [tab, setTab] = useState('Overview')

  return (
    <div style={{background:'#1e2433', border:'1px solid #2d3748', borderRadius:'12px', overflow:'hidden'}}>
      <div style={{display:'flex', borderBottom:'1px solid #2d3748'}}>
        {tabs.map(t => (
          <button key={t} onClick={() => setTab(t)}
            style={{padding:'12px 20px', fontSize:'13px', border:'none', cursor:'pointer',
              background:'transparent', color: tab===t ? '#60a5fa' : '#64748b',
              borderBottom: tab===t ? '2px solid #60a5fa' : '2px solid transparent'}}>
            {t}
          </button>
        ))}
      </div>

      <div style={{padding:'24px'}}>
        {tab === 'Overview' && (
          <div>
            <div style={{display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:'12px', marginBottom:'20px'}}>
              {[
                ['Entities', (data.entities?.persons?.length||0)+(data.entities?.places?.length||0)+(data.entities?.times?.length||0)+(data.entities?.orgs?.length||0)],
                ['Anomalies', data.anomalies?.length||0],
                ['Timeline Events', data.timeline?.length||0],
                ['Key Findings', data.key_findings?.length||0],
              ].map(([label, val]) => (
                <div key={label} style={{background:'#0f1117', borderRadius:'8px', padding:'16px'}}>
                  <p style={{fontSize:'11px', color:'#64748b', marginBottom:'6px'}}>{label}</p>
                  <p style={{fontSize:'24px', fontWeight:'600', color:'#f1f5f9'}}>{val}</p>
                </div>
              ))}
            </div>
            <div style={{background:'#0f1117', borderRadius:'8px', padding:'16px', marginBottom:'12px'}}>
              <p style={{fontSize:'11px', color:'#64748b', marginBottom:'8px', textTransform:'uppercase'}}>Case summary</p>
              <p style={{fontSize:'13px', lineHeight:'1.7', color:'#cbd5e1'}}>{data.summary}</p>
            </div>
            <div style={{background:'#0f1117', borderRadius:'8px', padding:'16px'}}>
              <p style={{fontSize:'11px', color:'#64748b', marginBottom:'8px', textTransform:'uppercase'}}>Key findings</p>
              {(data.key_findings||[]).map((f,i) => (
                <p key={i} style={{fontSize:'13px', color:'#cbd5e1', padding:'6px 0',
                  borderBottom:'1px solid #1e2433', lineHeight:'1.5'}}>→ {f}</p>
              ))}
            </div>
          </div>
        )}
        {tab === 'Entities'   && <EntityView data={data.entities} highlighted={data.highlighted_text} />}
        {tab === 'Anomalies'  && <AnomalyList anomalies={data.anomalies} />}
        {tab === 'Timeline'   && <Timeline events={data.timeline} />}
        {tab === 'Report'     && <ReportExport data={data} />}
      </div>
    </div>
  )
}