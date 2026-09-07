export default function StatTile({ label, value, color = 'var(--text1)', icon: Icon }) {
  return (
    <div style={{
      background: 'var(--bg1)', borderRadius: 'var(--radius-md)',
      padding: 'var(--space-4)', border: '1px solid var(--border)',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: 'var(--space-2)' }}>
        {Icon && <Icon size={12} color="var(--text3)" />}
        <p style={{
          fontSize: 'var(--text-xs)', color: 'var(--text3)',
          textTransform: 'uppercase', letterSpacing: '0.05em',
        }}>{label}</p>
      </div>
      <p style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color, fontFamily: 'var(--font-ui)' }}>{value}</p>
    </div>
  )
}
