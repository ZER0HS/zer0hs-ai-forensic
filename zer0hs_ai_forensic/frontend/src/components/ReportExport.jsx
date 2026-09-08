export default function ReportExport({ data }) {
  const now = new Date().toISOString().slice(0,19).replace('T',' ')
  const v   = data.case_verdict || {}
  const ind = data.indicators   || {}

  const report = [
    `FORENSIC AI ANALYSIS REPORT`,
    `Generated : ${now}`,
    `Agent     : claude-sonnet-4-5 + AbuseIPDB + VirusTotal`,
    `${'═'.repeat(56)}`,
    ``,
    `CASE VERDICT`,
    `  Verdict    : ${v.verdict || 'N/A'} (${v.verdict === 'TP' ? 'True Positive' : 'False Positive'})`,
    `  Risk Level : ${(v.risk_level || '').toUpperCase()}`,
    `  Confidence : ${v.confidence || 0}%`,
    ``,
    `CASE SUMMARY`,
    v.case_summary || data.summary || 'N/A',
    ``,
    `AI REASONING`,
    v.reasoning || 'N/A',
    ``,
    `KEY FINDINGS`,
    ...(data.key_findings||[]).map(f => `  • ${f}`),
    ``,
    `EXTRACTED INDICATORS`,
    `  Public IPs  : ${(ind.ips||[]).join(', ')    || 'none'}`,
    `  Private IPs : ${(ind.private_ips||[]).join(', ') || 'none'}`,
    `  Domains     : ${(ind.domains||[]).join(', ')|| 'none'}`,
    `  Emails      : ${(ind.emails||[]).join(', ') || 'none'}`,
    `  URLs        : ${(ind.urls||[]).join(', ')   || 'none'}`,
    ``,
    `THREAT INTELLIGENCE RESULTS`,
    ...(data.threat_results||[]).map(r =>
      `  [${r.type.toUpperCase()}] ${r.value} — Score: ${r.abuse_score||0} — ${r.country||''} ${r.isp||''} (${r.source})`
    ),
    ``,
    `ENTITIES`,
    `  Persons : ${(data.entities?.persons||[]).join(', ') || 'none'}`,
    `  Places  : ${(data.entities?.places||[]).join(', ')  || 'none'}`,
    `  Times   : ${(data.entities?.times||[]).join(', ')   || 'none'}`,
    `  Orgs    : ${(data.entities?.orgs||[]).join(', ')    || 'none'}`,
    ``,
    `ANOMALIES (${(data.anomalies||[]).length})`,
    ...(data.anomalies||[]).map(a => `  [${a.severity.toUpperCase()}] ${a.title}: ${a.description}`),
    ``,
    `MITRE ATT&CK`,
    ...(v.mitre_techniques||[]).map(t => `  ${t}`),
    ``,
    `IOCS`,
    ...(v.iocs||[]).map(i => `  ${i}`),
    ``,
    `RECOMMENDED ACTIONS`,
    ...(v.recommended_actions||[]).map(a => `  → ${a}`),
    ``,
    `TIMELINE`,
    ...(data.timeline||[]).map(e => `  ${e.time} | ${e.event}${e.actors?' ('+e.actors+')':''}${e.anomaly?' ⚠':''}`),
    ``,
    `${'═'.repeat(56)}`,
    `END OF REPORT`
  ].join('\n')

  function download(fmt) {
    const content = fmt === 'json' ? JSON.stringify(data, null, 2) : report
    const blob = new Blob([content], {type: fmt==='json'?'application/json':'text/plain'})
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `forensic_report.${fmt}`
    a.click()
  }

  return (
    <div>
      <pre style={{
        background:'var(--bg1)', borderRadius:'12px', padding:'20px',
        fontSize:'11px', fontFamily:'monospace', lineHeight:'1.8',
        color:'var(--text2)', overflowX:'auto', marginBottom:'16px',
        whiteSpace:'pre-wrap', border:'1px solid var(--border)',
        maxHeight:'500px', overflowY:'auto'
      }}>{report}</pre>
      <div style={{display:'flex', gap:'8px'}}>
        {['txt','json'].map(fmt => (
          <button key={fmt} onClick={() => download(fmt)} style={{
            padding:'9px 18px', background:'var(--bg3)', color:'var(--text2)',
            border:'1px solid var(--border)', borderRadius:'8px',
            fontSize:'12px', cursor:'pointer', transition:'all 0.15s'
          }}>Export .{fmt}</button>
        ))}
      </div>
    </div>
  )
}