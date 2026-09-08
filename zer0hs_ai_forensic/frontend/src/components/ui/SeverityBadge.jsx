import { severityConfig } from './severity'

export default function SeverityBadge({ severity, size = 'md' }) {
  const cfg = severityConfig(severity)
  const Icon = cfg.icon
  const compact = size === 'sm'

  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '5px',
      padding: compact ? '2px 8px' : '4px 10px',
      borderRadius: 'var(--radius-sm)',
      background: cfg.bg,
      border: `1px solid ${cfg.border}`,
      color: cfg.color,
      fontSize: compact ? 'var(--text-xs)' : 'var(--text-sm)',
      fontWeight: 600,
      textTransform: 'uppercase',
      letterSpacing: '0.04em',
      whiteSpace: 'nowrap',
    }}>
      <Icon size={compact ? 11 : 13} strokeWidth={2.5} />
      {cfg.label}
    </span>
  )
}
