import { useQuery, useSubscription } from '@apollo/client'
import { DASHBOARD, METRICS_STREAM } from '../graphql/operations'
import { Card, ErrorBanner, PageHeader, Stat, fmtDate, fmtNum } from './ui'

interface Metrics {
  timestamp: string
  throughputMbps: number
  packetsPerSecond: number
  activeFlows: number
  avgLatencyMs: number
  avgPacketLoss: number
  cpuUsage: number
  memoryUsage: number
}

interface DashboardData {
  health: string
  version: string
  siteCount: number
  sites: { id: string; name: string; status: string }[]
  paths: { id: string; status: string; qualityScore: number }[]
  policies: { id: string; enabled: boolean }[]
  metrics: Metrics
}

export default function Dashboard() {
  const { data, error, loading } = useQuery<DashboardData>(DASHBOARD, { pollInterval: 15000 })
  // Live push over the GraphQL WebSocket; falls back to the polled value.
  const live = useSubscription<{ metricsStream: Metrics }>(METRICS_STREAM)
  const metrics = live.data?.metricsStream ?? data?.metrics

  const sitesDown = data?.sites.filter((s) => s.status !== 'ACTIVE').length ?? 0
  const pathsFailed = data?.paths.filter((p) => p.status === 'FAILED').length ?? 0
  const pathsDegraded = data?.paths.filter((p) => p.status === 'DEGRADED').length ?? 0
  const policiesOn = data?.policies.filter((p) => p.enabled).length ?? 0

  return (
    <div>
      <PageHeader title="Dashboard" />
      <ErrorBanner error={error} />
      {loading && !data && <p className="text-gray-500">Loading…</p>}
      {data && (
        <>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4 mb-6">
            <Stat label="Sites" value={data.siteCount} hint={sitesDown ? `${sitesDown} not active` : 'all active'} to="/sites" />
            <Stat
              label="Paths"
              value={data.paths.length}
              hint={data.paths.length ? `${pathsFailed} failed, ${pathsDegraded} degraded` : 'none discovered yet'}
              to="/paths"
            />
            <Stat label="Policies" value={data.policies.length} hint={`${policiesOn} enabled`} to="/policies" />
            <Stat label="Active flows" value={metrics?.activeFlows ?? '—'} hint="see traffic history" to="/traffic" />
          </div>
          <Card title="Live system metrics">
            {metrics ? (
              <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4 text-sm">
                <div><dt className="text-gray-500">Throughput</dt><dd className="text-xl font-semibold">{fmtNum(metrics.throughputMbps, 2)} Mbps</dd></div>
                <div><dt className="text-gray-500">Packets/s</dt><dd className="text-xl font-semibold">{metrics.packetsPerSecond}</dd></div>
                <div><dt className="text-gray-500">Avg latency</dt><dd className="text-xl font-semibold">{fmtNum(metrics.avgLatencyMs)} ms</dd></div>
                <div><dt className="text-gray-500">Avg packet loss</dt><dd className="text-xl font-semibold">{fmtNum(metrics.avgPacketLoss, 2)} %</dd></div>
                <div><dt className="text-gray-500">CPU</dt><dd className="text-xl font-semibold">{fmtNum(metrics.cpuUsage)} %</dd></div>
                <div><dt className="text-gray-500">Memory</dt><dd className="text-xl font-semibold">{fmtNum(metrics.memoryUsage)} %</dd></div>
                <div className="col-span-2">
                  <dt className="text-gray-500">Last update</dt>
                  <dd className="text-sm">{fmtDate(metrics.timestamp)} {live.data ? '(live)' : '(polled)'}</dd>
                </div>
              </dl>
            ) : (
              <p className="text-gray-500">No metrics yet.</p>
            )}
            <p className="mt-4 text-xs text-gray-400">
              API {data.health} · {data.version}
            </p>
          </Card>
        </>
      )}
    </div>
  )
}
