import { useState } from 'react'

export default function FileUpload({ onAnalyze, loading, progress }) {
  const [file, setFile] = useState(null)
  const [text, setText] = useState('')
  const [drag, setDrag] = useState(false)

  function handleDrop(e) {
    e.preventDefault(); setDrag(false)
    const f = e.dataTransfer.files[0]
    if (f) setFile(f)
  }

  return (
    <div style={{
      background:'var(--bg2)',
      border:'1px solid var(--border)',
      borderRadius:'16px',
      padding:'24px',
      marginBottom:'28px'
    }}>
      <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:'16px', marginBottom:'16px'}}>

        {/* Drop zone */}
        <div
          onDragOver={e=>{e.preventDefault();setDrag(true)}}
          onDragLeave={()=>setDrag(false)}
          onDrop={handleDrop}
          onClick={() => document.getElementById('fi').click()}
          style={{
            border: `1.5px dashed ${drag ? 'var(--blue)' : 'var(--border2)'}`,
            borderRadius:'12px', padding:'28px 20px',
            textAlign:'center', cursor:'pointer',
            background: drag ? 'rgba(59,130,246,0.05)' : 'var(--bg1)',
            transition:'all 0.2s'
          }}>
          <div style={{fontSize:'28px', marginBottom:'8px'}}>📁</div>
          <p style={{fontSize:'13px', color: file ? 'var(--blue)' : 'var(--text2)', fontWeight: file ? '500' : '400'}}>
            {file ? file.name : 'Drop file or click to upload'}
          </p>
          <p style={{fontSize:'11px', color:'var(--text3)', marginTop:'4px'}}>
            .eml .txt .log .zip .csv
          </p>
          <input id="fi" type="file" accept=".txt,.eml,.log,.zip,.csv,.json"
            style={{display:'none'}} onChange={e => setFile(e.target.files[0])} />
        </div>

        {/* Text paste */}
        <div style={{display:'flex', flexDirection:'column'}}>
          <p style={{fontSize:'11px', color:'var(--text3)', marginBottom:'8px', textTransform:'uppercase', letterSpacing:'0.06em'}}>
            Or paste evidence text
          </p>
          <textarea
            value={text}
            onChange={e => setText(e.target.value)}
            placeholder="Paste email headers, chat logs, server logs..."
            style={{
              flex:1, background:'var(--bg1)', border:'1px solid var(--border)',
              borderRadius:'10px', padding:'12px', color:'var(--text1)',
              fontSize:'12px', fontFamily:'monospace', resize:'none', outline:'none',
              lineHeight:'1.6', transition:'border-color 0.15s'
            }}
            onFocus={e => e.target.style.borderColor='var(--border2)'}
            onBlur={e  => e.target.style.borderColor='var(--border)'}
          />
        </div>
      </div>

      <div style={{display:'flex', alignItems:'center', gap:'16px'}}>
        <button
          onClick={() => onAnalyze(file, text)}
          disabled={loading || (!file && !text.trim())}
          style={{
            padding:'11px 28px',
            background: loading ? 'var(--bg4)' : 'linear-gradient(135deg, #3b82f6, #6366f1)',
            color:'white', border:'none', borderRadius:'10px',
            fontSize:'13px', fontWeight:'600', cursor: loading ? 'not-allowed' : 'pointer',
            transition:'opacity 0.15s', opacity: (!file && !text.trim()) ? 0.4 : 1
          }}>
          {loading ? 'Analyzing...' : 'Run Full Analysis'}
        </button>

        {loading && progress && (
          <div style={{display:'flex', alignItems:'center', gap:'8px'}}>
            <div style={{
              width:'16px', height:'16px', border:'2px solid var(--border2)',
              borderTopColor:'var(--blue)', borderRadius:'50%',
              animation:'spin 0.8s linear infinite'
            }}/>
            <span style={{fontSize:'12px', color:'var(--text2)'}}>{progress}</span>
          </div>
        )}

        {file && !loading && (
          <button onClick={() => setFile(null)} style={{
            fontSize:'12px', color:'var(--text3)', background:'none',
            border:'none', cursor:'pointer', padding:'4px'
          }}>✕ clear file</button>
        )}
      </div>

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  )
}