import { useState } from 'react'
import EntityView from './EntityView'
import AnomalyList from './AnomalyList'
import Timeline from './Timeline'
import ReportExport from './ReportExport'
import ThreatResults from './ThreatResults'
import VerdictBanner from './VerdictBanner'
import EmailHeaders from './EmailHeaders'
import SandboxView from './SandboxView'

const tabs = [
  ['overview',  'Overview'],
  ['threat',    'Threat Intel'],
  ['headers',   'Email Headers'],
  ['sandbox',   'Sandbox'],
  ['entities',  'Entities'],
  ['anomalies', 'Anomalies'],
  ['timeline',  'Timeline'],
  ['report',    'Report'],
]

export default function ResultsView({ data }) {
  const [tab, setTab] = useState('overview')

  return (
    <div>
      <VerdictBanner verdict={data.case_verdict} caseId={data.case_id} />
      <div style={{background:'var(--bg2)', border:'1px solid var(--border)',
        borderRadius:'16px', overflow:'hidden', marginTop:'20px'}}>
        <div style={{display:'flex', borderBottom:'1px solid var(--border)',
          background:'var(--bg1)', padding:'0 8px', overflowX:'auto'}}>
          {tabs.map(([key, label]) => (
            <button key={key} onClick={() => setTab(key)} style={{
              padding:'14px 16px', fontSize:'13px', border:'none', cursor:'pointer',
              background:'transparent', whiteSpace:'nowrap',
              color: tab===key ? 'var(--blue)' : 'var(--text2)',
              borderBottom: tab===key ? '2px solid var(--blue)' : '2px solid transparent',
              fontWeight: tab===key ? '500' : '400', transition:'all 0.15s'
            }}>{label}</button>
          ))}
        </div>
        <div style={{padding:'24px'}}>
          {tab === 'overview'  && <Overview data={data} />}
          {tab === 'threat'    && <ThreatResults results={data.threat_results} indicators={data.indicators} />}
          {tab === 'headers'   && <EmailHeaders data={data.eml_headers} />}
          {tab === 'sandbox'   && <SandboxView urls={data.indicators?.urls} />}
          {tab === 'entities'  && <EntityView data={data.entities} highlighted={data.highlighted_text} />}
          {tab === 'anomalies' && <AnomalyList anomalies={data.anomalies} />}
          {tab === 'timeline'  && <Timeline events={data.timeline} />}
          {tab === 'report'    && <ReportExport data={data} />}
        </div>
      </div>
    </div>
  )
}

function Overview({ data }) {
  const v = data.case_verdict || {}
  const totalEntities = Object.values(data.entities||{}).flat().length

  return (
    <div>
      <div style={{display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:'12px', marginBottom:'20px'}}>
        {[
          ['Entities',          totalEntities,                   'var(--cyan)'],
          ['Anomalies',         data.anomalies?.length||0,       'var(--amber)'],
          ['Indicators checked',data.threat_results?.length||0,  'var(--purple)'],
          ['Timeline events',   data.timeline?.length||0,        'var(--green)'],
        ].map(([label, val, color]) => (
          <div key={label} style={{background:'var(--bg1)', borderRadius:'12px',
            padding:'16px', border:'1px solid var(--border)'}}>
            <p style={{fontSize:'11px', color:'var(--text3)', marginBottom:'6px',
              textTransform:'uppercase', letterSpacing:'0.05em'}}>{label}</p>
            <p style={{fontSize:'26px', fontWeight:'700', color}}>{val}</p>
          </div>
        ))}
      </div>
      <div style={{background:'var(--bg1)', borderRadius:'12px', padding:'18px',
        marginBottom:'14px', border:'1px solid var(--border)'}}>
        <p style={{fontSize:'11px', color:'var(--text3)', marginBottom:'8px',
          textTransform:'uppercase', letterSpacing:'0.05em'}}>Case summary</p>
        <p style={{fontSize:'13px', lineHeight:'1.75', color:'var(--text2)'}}>{data.summary}</p>
      </div>
      {v.recommended_actions?.length > 0 && (
        <div style={{background:'var(--bg1)', borderRadius:'12px', padding:'18px',
          border:'1px solid var(--border)'}}>
          <p style={{fontSize:'11px', color:'var(--text3)', marginBottom:'12px',
            textTransform:'uppercase', letterSpacing:'0.05em'}}>Recommended actions</p>
          {v.recommended_actions.map((a,i) => (
            <div key={i} style={{display:'flex', gap:'10px', padding:'8px 0',
              borderBottom:'1px solid var(--border)'}}>
              <span style={{color:'var(--blue)', fontSize:'12px', flexShrink:0}}>→</span>
              <span style={{fontSize:'13px', color:'var(--text2)', lineHeight:'1.5'}}>{a}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}