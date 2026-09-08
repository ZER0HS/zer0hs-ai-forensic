import { BarChart3, History, Package, ScanSearch, ShieldCheck, ShieldHalf } from 'lucide-react'

export const NAV_ITEMS = [
  ['evidence', 'Analyze',       ScanSearch],
  ['threat',   'Threat Intel',  ShieldHalf],
  ['sandbox',  'URL Sandbox',   Package],
  ['history',  'Case History',  History],
  ['accuracy', 'Accuracy',      BarChart3],
]

export default function Sidebar({ active, onNavigate }) {
  return (
    <aside style={{
      width: 'var(--sidebar-width)', flexShrink: 0, height: '100vh', position: 'sticky', top: 0,
      background: 'var(--bg1)', borderRight: '1px solid var(--border)',
      display: 'flex', flexDirection: 'column', padding: 'var(--space-4) var(--space-3)',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 8px 20px' }}>
        <div style={{
          width: '28px', height: '28px', borderRadius: 'var(--radius-sm)',
          background: 'linear-gradient(135deg, #3b82f6, #06b6d4)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexShrink: 0,
        }}>
          <ShieldCheck size={16} color="white" strokeWidth={2.4} />
        </div>
        <span style={{
          fontSize: 'var(--text-md)', fontWeight: 700, color: 'var(--text1)', letterSpacing: '-0.02em',
        }}>ZER0HS</span>
      </div>

      <nav style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
        {NAV_ITEMS.map(([key, label, Icon]) => {
          const isActive = active === key
          return (
            <button
              key={key}
              type="button"
              onClick={() => onNavigate(key)}
              style={{
                display: 'flex', alignItems: 'center', gap: '10px',
                padding: '9px 12px', fontSize: 'var(--text-base)', border: 'none',
                borderRadius: 'var(--radius-sm)', cursor: 'pointer', textAlign: 'left',
                background: isActive ? 'rgba(59,130,246,0.15)' : 'transparent',
                color: isActive ? 'var(--blue)' : 'var(--text2)',
                fontWeight: isActive ? 600 : 400,
                transition: 'all 0.15s',
              }}
            >
              <Icon size={16} strokeWidth={isActive ? 2.4 : 2} />
              {label}
            </button>
          )
        })}
      </nav>

      <div style={{ marginTop: 'auto', padding: '8px', fontSize: 'var(--text-xs)', color: 'var(--text3)' }}>
        v2.0.0 · runs fully local by default
      </div>
    </aside>
  )
}
