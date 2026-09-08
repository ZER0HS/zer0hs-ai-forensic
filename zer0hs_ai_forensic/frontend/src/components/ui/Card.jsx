export default function Card({ title, children, padding = 'var(--space-5)', style, ...rest }) {
  return (
    <div
      style={{
        background: 'var(--bg2)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius-lg)',
        padding,
        ...style,
      }}
      {...rest}
    >
      {title && (
        <p style={{
          fontSize: 'var(--text-xs)', color: 'var(--text3)', marginBottom: 'var(--space-3)',
          textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600,
        }}>
          {title}
        </p>
      )}
      {children}
    </div>
  )
}
