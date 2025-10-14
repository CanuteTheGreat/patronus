import { useQuery, useSubscription } from '@apollo/client'
import { GET_SITES, GET_METRICS, METRICS_SUBSCRIPTION } from '../graphql/queries'
import type { Site, Metrics } from '../types'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts'
import dayjs from 'dayjs'

export default function Dashboard() {
  const { data: sitesData, loading: sitesLoading } = useQuery(GET_SITES)
  const { data: metricsData, loading: metricsLoading } = useQuery(GET_METRICS)

  // Subscribe to real-time metrics updates
  useSubscription(METRICS_SUBSCRIPTION, {
    onData: ({ data }) => {
      console.log('Metrics updated:', data)
    },
  })

  const sites: Site[] = sitesData?.sites || []
  const metrics: Metrics | null = metricsData?.metrics || null

  const activeSites = sites.filter((s) => s.status === 'Active').length
  const degradedSites = sites.filter((s) => s.status === 'Degraded').length
  const downSites = sites.filter((s) => s.status === 'Down').length

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100">
          Dashboard
        </h1>
        <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
          Overview of your SD-WAN network
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Total Sites"
          value={sites.length}
          loading={sitesLoading}
          color="blue"
        />
        <StatCard
          title="Active Sites"
          value={activeSites}
          loading={sitesLoading}
          color="green"
        />
        <StatCard
          title="Degraded Sites"
          value={degradedSites}
          loading={sitesLoading}
          color="yellow"
        />
        <StatCard
          title="Down Sites"
          value={downSites}
          loading={sitesLoading}
          color="red"
        />
      </div>

      {/* Metrics Grid */}
      {metrics && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <MetricCard
            title="Throughput"
            value={`${metrics.throughputMbps.toFixed(2)} Mbps`}
            loading={metricsLoading}
          />
          <MetricCard
            title="Packets/sec"
            value={metrics.packetsPerSecond.toLocaleString()}
            loading={metricsLoading}
          />
          <MetricCard
            title="Active Flows"
            value={metrics.activeFlows.toLocaleString()}
            loading={metricsLoading}
          />
          <MetricCard
            title="Avg Latency"
            value={`${metrics.avgLatencyMs.toFixed(2)} ms`}
            loading={metricsLoading}
          />
        </div>
      )}

      {/* System Resources */}
      {metrics && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="card">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
              CPU Usage
            </h3>
            <div className="flex items-end space-x-2">
              <span className="text-4xl font-bold text-blue-600">
                {metrics.cpuUsage.toFixed(1)}%
              </span>
            </div>
            <div className="mt-4 w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
              <div
                className="bg-blue-600 h-2 rounded-full transition-all"
                style={{ width: `${metrics.cpuUsage}%` }}
              />
            </div>
          </div>

          <div className="card">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
              Memory Usage
            </h3>
            <div className="flex items-end space-x-2">
              <span className="text-4xl font-bold text-green-600">
                {metrics.memoryUsage.toFixed(1)}%
              </span>
            </div>
            <div className="mt-4 w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
              <div
                className="bg-green-600 h-2 rounded-full transition-all"
                style={{ width: `${metrics.memoryUsage}%` }}
              />
            </div>
          </div>
        </div>
      )}

      {/* Recent Sites */}
      <div className="card">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
          Recent Sites
        </h3>
        {sitesLoading ? (
          <div className="flex justify-center py-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
          </div>
        ) : sites.length === 0 ? (
          <p className="text-gray-500 dark:text-gray-400 text-center py-8">
            No sites configured
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead>
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Name
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Location
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Endpoints
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Updated
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {sites.slice(0, 5).map((site) => (
                  <tr key={site.id}>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-gray-100">
                      {site.name}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {site.location}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <StatusBadge status={site.status} />
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {site.endpointCount}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {dayjs(site.updatedAt).format('MMM D, YYYY HH:mm')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

function StatCard({
  title,
  value,
  loading,
  color,
}: {
  title: string
  value: number
  loading: boolean
  color: 'blue' | 'green' | 'yellow' | 'red'
}) {
  const colorClasses = {
    blue: 'text-blue-600',
    green: 'text-green-600',
    yellow: 'text-yellow-600',
    red: 'text-red-600',
  }

  return (
    <div className="card">
      <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">
        {title}
      </h3>
      {loading ? (
        <div className="mt-2 animate-pulse">
          <div className="h-8 bg-gray-200 dark:bg-gray-700 rounded w-16" />
        </div>
      ) : (
        <p className={`mt-2 text-3xl font-bold ${colorClasses[color]}`}>
          {value}
        </p>
      )}
    </div>
  )
}

function MetricCard({
  title,
  value,
  loading,
}: {
  title: string
  value: string
  loading: boolean
}) {
  return (
    <div className="card">
      <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">
        {title}
      </h3>
      {loading ? (
        <div className="mt-2 animate-pulse">
          <div className="h-8 bg-gray-200 dark:bg-gray-700 rounded w-24" />
        </div>
      ) : (
        <p className="mt-2 text-2xl font-bold text-gray-900 dark:text-gray-100">
          {value}
        </p>
      )}
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
  const statusClasses = {
    Active: 'badge-success',
    Degraded: 'badge-warning',
    Down: 'badge-danger',
  }

  return (
    <span className={`badge ${statusClasses[status as keyof typeof statusClasses]}`}>
      {status}
    </span>
  )
}
