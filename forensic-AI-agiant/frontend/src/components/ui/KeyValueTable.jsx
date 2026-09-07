// Aligned label/value rows with a monospace value column — the pattern
// EmailHeaders.jsx and ThreatChecker.jsx each re-implemented separately as
// flex space-between row pairs. `rows` is [[label, value, mono?], ...];
// falsy values are skipped automatically.
export default function KeyValueTable({ rows }) {
  const visible = rows.filter(([, v]) => v !== undefined && v !== null && v !== '')
  if (visible.length === 0) return null

  return (
    <div>
      {visible.map(([label, value, mono = true], i) => (
        <div key={label} style={{
          display: 'flex', gap: 'var(--space-3)', padding: '8px 0',
          borderBottom: i < visible.length - 1 ? '1px solid var(--border)' : 'none',
          fontSize: 'var(--text-base)',
        }}>
          <span style={{ color: 'var(--text3)', minWidth: '110px', flexShrink: 0 }}>{label}</span>
          <span style={{
            color: 'var(--text1)',
            fontFamily: mono ? 'var(--font-mono)' : 'inherit',
            wordBreak: 'break-all',
          }}>{value}</span>
        </div>
      ))}
    </div>
  )
}
