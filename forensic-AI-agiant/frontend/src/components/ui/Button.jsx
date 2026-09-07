const VARIANTS = {
  primary: {
    background: 'linear-gradient(135deg, #7c3aed, #6366f1)',
    color: 'white',
    border: 'none',
  },
  secondary: {
    background: 'var(--bg3)',
    color: 'var(--text2)',
    border: '1px solid var(--border)',
  },
  ghost: {
    background: 'transparent',
    color: 'var(--text2)',
    border: '1px solid transparent',
  },
}

export default function Button({ variant = 'primary', disabled, icon: Icon, children, style, type = 'button', ...rest }) {
  const v = VARIANTS[variant] || VARIANTS.primary
  return (
    <button
      type={type}
      disabled={disabled}
      style={{
        display: 'inline-flex', alignItems: 'center', gap: '6px',
        padding: '10px 20px',
        borderRadius: 'var(--radius-md)',
        fontSize: 'var(--text-base)',
        fontWeight: 600,
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.6 : 1,
        transition: 'opacity 0.15s',
        ...v,
        ...style,
      }}
      {...rest}
    >
      {Icon && <Icon size={14} />}
      {children}
    </button>
  )
}
