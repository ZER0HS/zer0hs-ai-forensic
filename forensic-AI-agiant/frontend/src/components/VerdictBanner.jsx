import { useState } from 'react'
import { AlertTriangle, Check, ThumbsDown, ThumbsUp } from 'lucide-react'
import { apiClient } from '../api'
import { severityConfig } from './ui/severity'

export default function VerdictBanner({ verdict, caseId }) {
  const [submitted, setSubmitted] = useState(false)
  const [feedback, setFeedback]   = useState(null)

  if (!verdict) return null

  const c       = severityConfig(verdict.risk_level)
  const isTP    = verdict.verdict === 'TP'
  const factors = verdict.fp_tp_factors || {}

  async function submitFeedback(isCorrect) {
    if (submitted || !caseId) return
    setFeedback(isCorrect)
    try {
      const form = new FormData()
      form.append('case_id',
        caseId)
      form.append('human_verdict',
        isCorrect
          ? verdict.verdict
          : verdict.verdict === 'TP' ? 'FP' : 'TP')
      form.append('is_correct', isCorrect)
      await apiClient.post('/feedback', form)
      setSubmitted(true)
    } catch(e) {
      console.error('Feedback error:', e)
    }
  }

  return (
    <div style={{display:'flex', flexDirection:'column', gap:'12px'}}>

      {/* ── Main verdict card ── */}
      <div style={{
        background:   c.bg,
        border:       `1px solid ${c.border}`,
        borderRadius: '16px',
        padding:      '24px',
        display:      'grid',
        gridTemplateColumns: 'auto 1fr auto',
        gap:          '24px',
        alignItems:   'center'
      }}>

        {/* Left — verdict pill */}
        <div style={{textAlign:'center', minWidth:'90px'}}>
          <div style={{
            fontSize:      '11px',
            color:         c.color,
            textTransform: 'uppercase',
            letterSpacing: '0.1em',
            marginBottom:  '6px',
            opacity:       0.7
          }}>
            AI Verdict
          </div>
          <div style={{
            fontSize:      '40px',
            fontWeight:    '800',
            color:         c.color,
            letterSpacing: '-0.02em',
            lineHeight:    1
          }}>
            {verdict.verdict}
          </div>
          <div style={{
            marginTop:    '8px',
            fontSize:     '11px',
            padding:      '3px 10px',
            background:   isTP
              ? 'rgba(239,68,68,0.2)'
              : 'rgba(16,185,129,0.2)',
            color:        isTP ? '#fca5a5' : '#6ee7b7',
            borderRadius: '20px',
            display:      'inline-block',
            fontWeight:   '500'
          }}>
            {isTP ? 'True Positive' : 'False Positive'}
          </div>
        </div>

        {/* Middle — summary + confidence bar */}
        <div>
          {/* Risk label + confidence bar */}
          <div style={{
            display:      'flex',
            alignItems:   'center',
            gap:          '10px',
            marginBottom: '10px'
          }}>
            <span style={{
              fontSize:      '12px',
              fontWeight:    '600',
              color:         c.color,
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
              minWidth:      '80px'
            }}>
              {verdict.risk_level} risk
            </span>

            {/* Confidence bar */}
            <div style={{
              flex:         1,
              height:       '5px',
              background:   'var(--bg4)',
              borderRadius: '3px',
              overflow:     'hidden'
            }}>
              <div style={{
                width:        `${verdict.confidence || 0}%`,
                height:       '100%',
                background:   c.accent,
                borderRadius: '3px',
                transition:   'width 1.2s ease'
              }}/>
            </div>

            <span style={{
              fontSize:   '13px',
              color:      c.color,
              fontWeight: '700',
              minWidth:   '40px',
              textAlign:  'right'
            }}>
              {verdict.confidence || 0}%
            </span>
          </div>

          {/* Case summary */}
          <p style={{
            fontSize:     '13px',
            color:        'var(--text2)',
            lineHeight:   '1.75',
            marginBottom: factors.deciding_factor ? '12px' : 0
          }}>
            {verdict.case_summary || verdict.reasoning}
          </p>

          {/* Deciding factor callout */}
          {factors.deciding_factor && (
            <div style={{
              padding:      '9px 14px',
              background:   'rgba(0,0,0,0.25)',
              borderRadius: '8px',
              borderLeft:   `3px solid ${c.accent}`,
              display:      'flex',
              gap:          '8px',
              alignItems:   'flex-start'
            }}>
              <span style={{
                fontSize:   '11px',
                color:      c.color,
                fontWeight: '600',
                flexShrink: 0,
                marginTop:  '1px'
              }}>
                Key factor:
              </span>
              <span style={{fontSize:'12px', color:'var(--text2)', lineHeight:'1.5'}}>
                {factors.deciding_factor}
              </span>
            </div>
          )}
        </div>

        {/* Right — severity breakdown + MITRE */}
        <div style={{minWidth:'170px'}}>

          {/* Severity bars */}
          {verdict.severity_breakdown &&
           Object.keys(verdict.severity_breakdown).length > 0 && (
            <div style={{marginBottom:'14px'}}>
              {Object.entries(verdict.severity_breakdown).map(([k, v]) => (
                <div key={k} style={{marginBottom:'8px'}}>
                  <div style={{
                    display:        'flex',
                    justifyContent: 'space-between',
                    marginBottom:   '3px'
                  }}>
                    <span style={{
                      fontSize:      '10px',
                      color:         'var(--text3)',
                      textTransform: 'capitalize'
                    }}>
                      {k.replace(/_/g, ' ')}
                    </span>
                    <span style={{fontSize:'10px', color: c.color}}>
                      {v}
                    </span>
                  </div>
                  <div style={{
                    height:       '3px',
                    background:   'var(--bg4)',
                    borderRadius: '2px',
                    overflow:     'hidden'
                  }}>
                    <div style={{
                      width:        `${v}%`,
                      height:       '100%',
                      background:   c.accent,
                      borderRadius: '2px',
                      opacity:      0.8,
                      transition:   'width 1s ease'
                    }}/>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* MITRE techniques */}
          {verdict.mitre_techniques?.length > 0 && (
            <div style={{display:'flex', flexDirection:'column', gap:'4px'}}>
              {verdict.mitre_techniques.slice(0, 3).map(t => (
                <span key={t} style={{
                  fontSize:     '10px',
                  padding:      '3px 8px',
                  background:   'rgba(139,92,246,0.15)',
                  color:        '#c4b5fd',
                  border:       '1px solid rgba(139,92,246,0.3)',
                  borderRadius: '4px',
                  fontFamily:   'monospace',
                  lineHeight:   '1.4',
                  wordBreak:    'break-word'
                }}>
                  {t}
                </span>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* ── TP vs FP factors row ── */}
      {(factors.factors_for_tp?.length > 0 ||
        factors.factors_for_fp?.length > 0) && (
        <div style={{
          display:             'grid',
          gridTemplateColumns: '1fr 1fr',
          gap:                 '12px'
        }}>

          {/* Factors FOR TP */}
          <div style={{
            background:   'rgba(239,68,68,0.05)',
            border:       '1px solid rgba(239,68,68,0.2)',
            borderRadius: '10px',
            padding:      '14px'
          }}>
            <p style={{
              fontSize:      '11px',
              color:         '#fca5a5',
              marginBottom:  '10px',
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
              fontWeight:    '600',
              display:       'flex',
              alignItems:    'center',
              gap:           '6px'
            }}>
              <AlertTriangle size={12} /> Factors supporting TP
            </p>
            {factors.factors_for_tp?.length > 0
              ? factors.factors_for_tp.map((f, i) => (
                  <div key={i} style={{
                    display:       'flex',
                    gap:           '8px',
                    padding:       '6px 0',
                    borderBottom:  '1px solid rgba(239,68,68,0.1)',
                    fontSize:      '12px',
                    color:         'var(--text2)',
                    lineHeight:    '1.5'
                  }}>
                    <span style={{color:'#ef4444', flexShrink:0}}>→</span>
                    {f}
                  </div>
                ))
              : (
                <p style={{fontSize:'12px', color:'var(--text3)'}}>
                  None identified
                </p>
              )
            }
          </div>

          {/* Factors FOR FP */}
          <div style={{
            background:   'rgba(16,185,129,0.05)',
            border:       '1px solid rgba(16,185,129,0.2)',
            borderRadius: '10px',
            padding:      '14px'
          }}>
            <p style={{
              fontSize:      '11px',
              color:         '#6ee7b7',
              marginBottom:  '10px',
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
              fontWeight:    '600',
              display:       'flex',
              alignItems:    'center',
              gap:           '6px'
            }}>
              <Check size={12} /> Factors supporting FP
            </p>
            {factors.factors_for_fp?.length > 0
              ? factors.factors_for_fp.map((f, i) => (
                  <div key={i} style={{
                    display:      'flex',
                    gap:          '8px',
                    padding:      '6px 0',
                    borderBottom: '1px solid rgba(16,185,129,0.1)',
                    fontSize:     '12px',
                    color:        'var(--text2)',
                    lineHeight:   '1.5'
                  }}>
                    <span style={{color:'#10b981', flexShrink:0}}>→</span>
                    {f}
                  </div>
                ))
              : (
                <p style={{fontSize:'12px', color:'var(--text3)'}}>
                  None identified
                </p>
              )
            }
          </div>
        </div>
      )}

      {/* ── Recommended actions ── */}
      {verdict.recommended_actions?.length > 0 && (
        <div style={{
          background:   'var(--bg2)',
          border:       '1px solid var(--border)',
          borderRadius: '10px',
          padding:      '14px 16px'
        }}>
          <p style={{
            fontSize:      '11px',
            color:         'var(--text3)',
            marginBottom:  '10px',
            textTransform: 'uppercase',
            letterSpacing: '0.06em'
          }}>
            Recommended actions
          </p>
          {verdict.recommended_actions.map((a, i) => (
            <div key={i} style={{
              display:      'flex',
              gap:          '10px',
              padding:      '7px 0',
              borderBottom: '1px solid var(--border)',
              fontSize:     '13px',
              color:        'var(--text2)',
              lineHeight:   '1.5'
            }}>
              <span style={{
                color:      c.accent,
                flexShrink: 0,
                fontWeight: '600'
              }}>
                {i + 1}.
              </span>
              {a}
            </div>
          ))}
        </div>
      )}

      {/* ── IOCs block ── */}
      {verdict.iocs?.length > 0 && (
        <div style={{
          background:   'rgba(239,68,68,0.04)',
          border:       '1px solid rgba(239,68,68,0.15)',
          borderRadius: '10px',
          padding:      '14px 16px'
        }}>
          <p style={{
            fontSize:      '11px',
            color:         '#fca5a5',
            marginBottom:  '10px',
            textTransform: 'uppercase',
            letterSpacing: '0.06em'
          }}>
            Confirmed IOCs ({verdict.iocs.length})
          </p>
          <div style={{display:'flex', flexWrap:'wrap', gap:'6px'}}>
            {verdict.iocs.map((ioc, i) => (
              <span key={i} style={{
                fontSize:     '12px',
                padding:      '4px 10px',
                background:   'rgba(239,68,68,0.1)',
                color:        '#fca5a5',
                border:       '1px solid rgba(239,68,68,0.25)',
                borderRadius: '6px',
                fontFamily:   'monospace'
              }}>
                {ioc}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* ── Threat actor profile ── */}
      {verdict.threat_actor_profile && (
        <div style={{
          background:   'rgba(139,92,246,0.05)',
          border:       '1px solid rgba(139,92,246,0.2)',
          borderRadius: '10px',
          padding:      '14px 16px'
        }}>
          <p style={{
            fontSize:      '11px',
            color:         '#c4b5fd',
            marginBottom:  '8px',
            textTransform: 'uppercase',
            letterSpacing: '0.06em'
          }}>
            Threat actor profile
          </p>
          <p style={{
            fontSize:   '13px',
            color:      'var(--text2)',
            lineHeight: '1.7'
          }}>
            {verdict.threat_actor_profile}
          </p>
        </div>
      )}

      {/* ── Human feedback ── */}
      <div style={{
        background:   'var(--bg2)',
        border:       '1px solid var(--border)',
        borderRadius: '10px',
        padding:      '12px 16px',
        display:      'flex',
        alignItems:   'center',
        gap:          '12px',
        flexWrap:     'wrap'
      }}>
        <span style={{fontSize:'12px', color:'var(--text3)'}}>
          Was this verdict correct?
        </span>

        {submitted ? (
          <div style={{display:'flex', alignItems:'center', gap:'8px'}}>
            <span style={{
              display: 'flex', alignItems: 'center', gap: '4px',
              fontSize:  '12px',
              color:     '#6ee7b7',
              fontWeight:'500'
            }}>
              <Check size={13} /> Feedback saved
            </span>
            <span style={{fontSize:'11px', color:'var(--text3)'}}>
              — helps improve accuracy over time
            </span>
          </div>
        ) : (
          <div style={{display:'flex', gap:'8px'}}>
            <button
              type="button"
              onClick={() => submitFeedback(true)}
              disabled={!caseId}
              style={{
                display:      'flex', alignItems: 'center', gap: '5px',
                padding:      '6px 16px',
                fontSize:     '12px',
                cursor:       caseId ? 'pointer' : 'not-allowed',
                background:   feedback === true
                  ? 'rgba(16,185,129,0.25)'
                  : 'rgba(16,185,129,0.1)',
                color:        '#6ee7b7',
                border:       '1px solid rgba(16,185,129,0.3)',
                borderRadius: '6px',
                fontWeight:   '500',
                transition:   'all 0.15s'
              }}>
              <ThumbsUp size={13} /> Correct
            </button>
            <button
              type="button"
              onClick={() => submitFeedback(false)}
              disabled={!caseId}
              style={{
                display:      'flex', alignItems: 'center', gap: '5px',
                padding:      '6px 16px',
                fontSize:     '12px',
                cursor:       caseId ? 'pointer' : 'not-allowed',
                background:   feedback === false
                  ? 'rgba(239,68,68,0.25)'
                  : 'rgba(239,68,68,0.1)',
                color:        '#fca5a5',
                border:       '1px solid rgba(239,68,68,0.3)',
                borderRadius: '6px',
                fontWeight:   '500',
                transition:   'all 0.15s'
              }}>
              <ThumbsDown size={13} /> Wrong verdict
            </button>
          </div>
        )}

        {/* Case ID */}
        {caseId && (
          <span style={{
            marginLeft:  'auto',
            fontSize:    '10px',
            color:       'var(--text3)',
            fontFamily:  'monospace',
            padding:     '3px 8px',
            background:  'var(--bg1)',
            border:      '1px solid var(--border)',
            borderRadius:'4px'
          }}>
            {caseId}
          </span>
        )}
      </div>

    </div>
  )
}