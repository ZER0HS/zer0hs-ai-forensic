import { useEffect, useState } from 'react'
import { BarChart3 } from 'lucide-react'
import { Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { apiClient } from '../api'
import { EmptyState, ErrorBanner, PageHeader, SkeletonList } from './CaseHistory'
import Card from './ui/Card'
import StatTile from './ui/StatTile'

const CHART_TOOLTIP_STYLE = {
  background: 'var(--bg3)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)',
  fontSize: 'var(--text-sm)', color: 'var(--text1)',
}

function legendLabel(value) {
  return <span style={{ color: 'var(--text2)', fontSize: 'var(--text-sm)' }}>{value}</span>
}

export default function AccuracyDashboard() {
  const [stats, setStats] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    apiClient.get('/accuracy')
      .then(r => setStats(r.data))
      .catch(() => setError('Could not load accuracy stats — is the backend running?'))
  }, [])

  if (error) return <ErrorBanner message={error} />
  if (stats === null) return <SkeletonList rows={2} />

  const dist = stats.verdict_distribution || { TP: 0, FP: 0, unknown: 0 }
  const totalAnalyzed = dist.TP + dist.FP + dist.unknown

  const distData = [
    { name: 'True Positive', value: dist.TP, color: 'var(--red)' },
    { name: 'False Positive', value: dist.FP, color: 'var(--green)' },
  ].filter(d => d.value > 0)

  return (
    <div>
      <PageHeader
        title="Accuracy"
        subtitle="Precision and recall computed from human feedback on past cases — the more verdicts you correct, the more this reflects real-world accuracy."
      />

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 'var(--space-3)', marginBottom: 'var(--space-5)' }}>
        <StatTile label="Cases analyzed" value={totalAnalyzed} color="var(--cyan)" />
        <StatTile label="Reviewed by a human" value={stats.total_reviewed ?? 0} color="var(--purple)" />
        <StatTile label="Accuracy" value={stats.accuracy != null ? `${stats.accuracy}%` : '—'} color="var(--green)" />
        <StatTile label="Precision / Recall" value={
          stats.precision != null ? `${stats.precision}% / ${stats.recall}%` : '—'
        } color="var(--blue)" />
      </div>

      {stats.total_reviewed === 0 ? (
        <EmptyState
          icon={BarChart3}
          title="No feedback yet"
          body="Precision and recall need at least one case marked correct/incorrect from the Analyze tab's verdict card. The verdict split below already reflects every case analyzed so far."
        />
      ) : (
        <Card title="False positives vs. false negatives" style={{ marginBottom: 'var(--space-4)' }}>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={[
              { name: 'False positives', count: stats.false_positives || 0 },
              { name: 'False negatives', count: stats.false_negatives || 0 },
            ]}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis dataKey="name" stroke="var(--text3)" fontSize={12} />
              <YAxis stroke="var(--text3)" fontSize={12} allowDecimals={false} />
              <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
              <Bar dataKey="count" fill="var(--orange)" radius={[6, 6, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </Card>
      )}

      {distData.length > 0 && (
        <Card title="Verdict distribution (all analyzed cases)">
          <ResponsiveContainer width="100%" height={240}>
            <PieChart>
              <Pie data={distData} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80} paddingAngle={3}>
                {distData.map(d => <Cell key={d.name} fill={d.color} />)}
              </Pie>
              <Legend formatter={legendLabel} />
              <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
            </PieChart>
          </ResponsiveContainer>
        </Card>
      )}
    </div>
  )
}
