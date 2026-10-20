import { useMemo, useState } from 'react'
import { useQuery } from '@apollo/client'
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { format } from 'date-fns'
import { METRICS_HISTORY } from '../graphql/operations'
import { Card, Empty, ErrorBanner, PageHeader } from './ui'

interface Point {
  timestamp: string
  throughputMbps: number
  packetsPerSecond: number
  activeFlows: number
  avgLatencyMs: number
  avgPacketLoss: number
}

const RANGES = [
  { label: '15 min', minutes: 15 },
  { label: '1 hour', minutes: 60 },
  { label: '24 hours', minutes: 24 * 60 },
]

export default function Traffic() {
  const [minutes, setMinutes] = useState(60)
  // Recompute the window when the range changes; polling refreshes it.
  const vars = useMemo(() => {
    const to = new Date()
    return { from: new Date(to.getTime() - minutes * 60_000).toISOString(), to: to.toISOString() }
  }, [minutes])
  const { data, error, loading } = useQuery<{ metricsHistory: Point[] }>(METRICS_HISTORY, { variables: vars, pollInterval: 30000 })

  const points = (data?.metricsHistory ?? []).map((p) => ({
    ...p,
    time: format(new Date(p.timestamp), minutes > 60 ? 'MM-dd HH:mm' : 'HH:mm:ss'),
  }))

  return (
    <div>
      <PageHeader title="Traffic">
        {RANGES.map((r) => (
          <button
            key={r.minutes}
            onClick={() => setMinutes(r.minutes)}
            className={`rounded-lg px-3 py-1.5 text-sm ${minutes === r.minutes ? 'bg-primary-600 text-white' : 'bg-white ring-1 ring-gray-300'}`}
          >
            {r.label}
          </button>
        ))}
      </PageHeader>
      <ErrorBanner error={error} />
      {loading && !data && <p className="text-gray-500">Loading…</p>}
      {data && points.length === 0 && <Empty>No metrics were recorded in this window.</Empty>}
      {points.length > 0 && (
        <div className="space-y-6">
          <Card title="Throughput and flows">
            <ResponsiveContainer width="100%" height={280}>
              <LineChart data={points}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis yAxisId="left" />
                <YAxis yAxisId="right" orientation="right" />
                <Tooltip />
                <Legend />
                <Line yAxisId="left" type="monotone" dataKey="throughputMbps" name="Throughput (Mbps)" stroke="#0ea5e9" dot={false} />
                <Line yAxisId="right" type="monotone" dataKey="activeFlows" name="Active flows" stroke="#8b5cf6" dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </Card>
          <Card title="Latency and loss">
            <ResponsiveContainer width="100%" height={280}>
              <LineChart data={points}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis yAxisId="left" />
                <YAxis yAxisId="right" orientation="right" />
                <Tooltip />
                <Legend />
                <Line yAxisId="left" type="monotone" dataKey="avgLatencyMs" name="Avg latency (ms)" stroke="#10b981" dot={false} />
                <Line yAxisId="right" type="monotone" dataKey="avgPacketLoss" name="Avg loss (%)" stroke="#ef4444" dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </Card>
        </div>
      )}
    </div>
  )
}
