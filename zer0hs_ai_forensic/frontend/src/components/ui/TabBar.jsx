export default function TabBar({ tabs, value, onChange }) {
  return (
    <div style={{
      display: 'flex', borderBottom: '1px solid var(--border)',
      background: 'var(--bg1)', padding: '0 8px', overflowX: 'auto',
    }}>
      {tabs.map(([key, label, Icon]) => (
        <button
          key={key}
          type="button"
          onClick={() => onChange(key)}
          style={{
            display: 'flex', alignItems: 'center', gap: '6px',
            padding: '14px 16px', fontSize: 'var(--text-base)', border: 'none', cursor: 'pointer',
            background: 'transparent', whiteSpace: 'nowrap',
            color: value === key ? 'var(--blue)' : 'var(--text2)',
            borderBottom: value === key ? '2px solid var(--blue)' : '2px solid transparent',
            fontWeight: value === key ? 600 : 400, transition: 'all 0.15s',
          }}
        >
          {Icon && <Icon size={14} />}
          {label}
        </button>
      ))}
    </div>
  )
}
