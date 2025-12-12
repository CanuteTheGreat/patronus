import { useState, useEffect } from 'react'
import { useQuery, useSubscription } from '@apollo/client'
import { Link } from 'react-router-dom'
import {
  GET_SITES,
  GET_METRICS,
  GET_PATHS,
  GET_POLICIES,
  GET_AUDIT_LOGS,
  METRICS_SUBSCRIPTION,
  SYSTEM_ALERTS_SUBSCRIPTION,
} from '../graphql/queries'
import type { Site, Metrics, Path, Policy, AuditLog, SystemAlert } from '../types'
import { formatNumber, formatBytes, getQualityColor, getStatusColor } from '../types'
import {
  ArrowTrendingUpIcon,
  ArrowTrendingDownIcon,
  BuildingOfficeIcon,
  DocumentTextIcon,
  SignalIcon,
  ClockIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  BellAlertIcon,
  ArrowPathIcon,
  PlusIcon,
  ChartBarIcon,
} from '@heroicons/react/24/outline'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'
import dayjs from 'dayjs'
import relativeTime from 'dayjs/plugin/relativeTime'
import Loading from '../components/Loading'

dayjs.extend(relativeTime)

export default function Dashboard() {
  const [realtimeMetrics, setRealtimeMetrics] = useState<Metrics[]>([])
  const [alerts, setAlerts] = useState<SystemAlert[]>([])

  const { data: sitesData, loading: sitesLoading } = useQuery(GET_SITES)
  const { data: metricsData, loading: metricsLoading } = useQuery(GET_METRICS)
  const { data: pathsData, loading: pathsLoading } = useQuery(GET_PATHS)
  const { data: policiesData, loading: policiesLoading } = useQuery(GET_POLICIES)
  const { data: auditData } = useQuery(GET_AUDIT_LOGS, {
    variables: { limit: 5 },
  })

  // Subscribe to real-time metrics updates
  useSubscription(METRICS_SUBSCRIPTION, {
    variables: { intervalSeconds: 10 },
    onData: ({ data }) => {
      if (data?.data?.metricsStream) {
        setRealtimeMetrics((prev) => {
          const updated = [...prev, data.data.metricsStream]
          return updated.slice(-30) // Keep last 30 data points
        })
      }
    },
  })

  // Subscribe to system alerts
  useSubscription(SYSTEM_ALERTS_SUBSCRIPTION, {
    onData: ({ data }) => {
      if (data?.data?.systemAlerts) {
        setAlerts((prev) => [data.data.systemAlerts, ...prev].slice(0, 10))
      }
    },
  })

  const sites: Site[] = sitesData?.sites || []
  const metrics: Metrics | null = metricsData?.metrics || null
  const paths: Path[] = pathsData?.paths || []
  const policies: Policy[] = policiesData?.policies || []
  const recentActivity: AuditLog[] = auditData?.auditLogs || []

  const activeSites = sites.filter((s) => s.status === 'Active').length
  const degradedSites = sites.filter((s) => s.status === 'Degraded').length
  const downSites = sites.filter((s) => s.status === 'Down').length

  const activePaths = paths.filter((p) => p.status === 'Active').length
  const avgQuality = paths.length > 0
    ? paths.reduce((acc, p) => acc + p.qualityScore, 0) / paths.length
    : 0

  const enabledPolicies = policies.filter((p) => p.enabled).length

  // Prepare chart data
  const chartData = realtimeMetrics.length > 0
    ? realtimeMetrics.map((m) => ({
        time: dayjs(m.timestamp).format('HH:mm:ss'),
        throughput: m.throughputMbps,
        latency: m.avgLatencyMs,
      }))
    : metrics
    ? [{ time: 'Now', throughput: metrics.throughputMbps, latency: metrics.avgLatencyMs }]
    : []

  const isLoading = sitesLoading || metricsLoading || pathsLoading || policiesLoading

  if (isLoading) {
    return <Loading message="Loading dashboard..." />
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100">
            Dashboard
          </h1>
          <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
            Overview of your SD-WAN network
          </p>
        </div>
        <div className="mt-4 md:mt-0 flex space-x-3">
          <Link to="/sites" className="btn btn-primary flex items-center">
            <PlusIcon className="w-5 h-5 mr-2" />
            Add Site
          </Link>
          <button className="btn btn-secondary flex items-center">
            <ArrowPathIcon className="w-5 h-5 mr-2" />
            Refresh
          </button>
        </div>
      </div>

      {/* Alerts Banner */}
      {(downSites > 0 || alerts.filter(a => a.severity === 'Critical').length > 0) && (
        <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 rounded-lg p-4">
          <div className="flex items-start">
            <BellAlertIcon className="w-6 h-6 text-red-600 dark:text-red-400 mr-3 flex-shrink-0" />
            <div>
              <h3 className="text-sm font-semibold text-red-800 dark:text-red-200">
                Attention Required
              </h3>
              <div className="mt-1 text-sm text-red-700 dark:text-red-300">
                {downSites > 0 && (
                  <p>{downSites} site{downSites > 1 ? 's are' : ' is'} currently down.</p>
                )}
                {alerts.filter(a => a.severity === 'Critical').slice(0, 3).map((alert) => (
                  <p key={alert.id}>{alert.message}</p>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Total Sites"
          value={sites.length}
          icon={<BuildingOfficeIcon className="w-6 h-6" />}
          color="blue"
          subtext={`${activeSites} active, ${degradedSites} degraded, ${downSites} down`}
          link="/sites"
        />
        <StatCard
          title="Active Paths"
          value={activePaths}
          total={paths.length}
          icon={<SignalIcon className="w-6 h-6" />}
          color="green"
          subtext={`Avg quality: ${avgQuality.toFixed(1)}%`}
          link="/topology"
        />
        <StatCard
          title="Policies"
          value={enabledPolicies}
          total={policies.length}
          icon={<DocumentTextIcon className="w-6 h-6" />}
          color="purple"
          subtext={`${policies.length - enabledPolicies} disabled`}
          link="/policies"
        />
        <StatCard
          title="Throughput"
          value={metrics ? `${metrics.throughputMbps.toFixed(1)}` : '0'}
          unit="Mbps"
          icon={<ChartBarIcon className="w-6 h-6" />}
          color="indigo"
          subtext={metrics ? `${formatNumber(metrics.packetsPerSecond)} pps` : ''}
          link="/metrics"
        />
      </div>

      {/* Network Metrics */}
      {metrics && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <MetricCard
            title="Active Flows"
            value={formatNumber(metrics.activeFlows)}
            icon={<ArrowTrendingUpIcon className="w-5 h-5" />}
          />
          <MetricCard
            title="Avg Latency"
            value={`${metrics.avgLatencyMs.toFixed(2)} ms`}
            icon={<ClockIcon className="w-5 h-5" />}
            status={metrics.avgLatencyMs > 100 ? 'warning' : 'success'}
          />
          <MetricCard
            title="Packet Loss"
            value={`${metrics.avgPacketLoss.toFixed(3)}%`}
            icon={metrics.avgPacketLoss > 1 ? <ArrowTrendingDownIcon className="w-5 h-5" /> : <CheckCircleIcon className="w-5 h-5" />}
            status={metrics.avgPacketLoss > 1 ? 'danger' : metrics.avgPacketLoss > 0.5 ? 'warning' : 'success'}
          />
          <MetricCard
            title="System Load"
            value={`${metrics.cpuUsage.toFixed(1)}%`}
            subtext={`Memory: ${metrics.memoryUsage.toFixed(1)}%`}
            status={metrics.cpuUsage > 90 ? 'danger' : metrics.cpuUsage > 75 ? 'warning' : 'success'}
          />
        </div>
      )}

      {/* Charts and Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Throughput Chart */}
        <div className="lg:col-span-2 card">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
            Network Throughput
          </h3>
          {chartData.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <AreaChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="time" stroke="#9ca3af" fontSize={12} />
                <YAxis stroke="#9ca3af" fontSize={12} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1f2937',
                    border: 'none',
                    borderRadius: '8px',
                    color: '#f3f4f6',
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="throughput"
                  stroke="#3b82f6"
                  fill="#3b82f6"
                  fillOpacity={0.3}
                  name="Throughput (Mbps)"
                />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[250px] text-gray-500">
              No data available
            </div>
          )}
        </div>

        {/* Recent Activity */}
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
            Recent Activity
          </h3>
          {recentActivity.length > 0 ? (
            <div className="space-y-4">
              {recentActivity.map((log) => (
                <div key={log.id} className="flex items-start space-x-3">
                  <div className={`w-2 h-2 mt-2 rounded-full ${getEventColor(log.eventType)}`} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-gray-900 dark:text-gray-100 truncate">
                      {log.description}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                      {dayjs(log.timestamp).fromNow()}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-500 dark:text-gray-400 text-sm text-center py-8">
              No recent activity
            </p>
          )}
        </div>
      </div>

      {/* Path Quality Overview */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
            Path Quality Overview
          </h3>
          <Link to="/topology" className="text-sm text-blue-600 dark:text-blue-400 hover:underline">
            View Topology
          </Link>
        </div>
        {paths.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead>
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Path
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Latency
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Loss
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Bandwidth
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Quality
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {paths.slice(0, 5).map((path) => {
                  const sourceSite = sites.find(s => s.id === path.sourceSiteId)
                  const destSite = sites.find(s => s.id === path.destinationSiteId)
                  return (
                    <tr key={path.id}>
                      <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100">
                        {sourceSite?.name || 'Unknown'} → {destSite?.name || 'Unknown'}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        <span className={`badge ${path.status === 'Active' ? 'badge-success' : path.status === 'Degraded' ? 'badge-warning' : 'badge-danger'}`}>
                          {path.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                        {path.latencyMs.toFixed(2)} ms
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                        {path.packetLoss.toFixed(2)}%
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                        {path.bandwidthMbps.toFixed(1)} Mbps
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        <span className={`font-medium ${getQualityColor(path.qualityScore)}`}>
                          {path.qualityScore.toFixed(1)}%
                        </span>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-gray-500 dark:text-gray-400 text-center py-8">
            No paths configured. Add sites to create network paths.
          </p>
        )}
      </div>

      {/* Site Status */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
            Site Status
          </h3>
          <Link to="/sites" className="text-sm text-blue-600 dark:text-blue-400 hover:underline">
            View All Sites
          </Link>
        </div>
        {sites.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {sites.slice(0, 6).map((site) => (
              <div
                key={site.id}
                className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
              >
                <div>
                  <h4 className="font-medium text-gray-900 dark:text-gray-100">{site.name}</h4>
                  <p className="text-sm text-gray-500 dark:text-gray-400">{site.location}</p>
                </div>
                <div className="flex items-center space-x-2">
                  <span className={`w-3 h-3 rounded-full ${site.status === 'Active' ? 'bg-green-500' : site.status === 'Degraded' ? 'bg-yellow-500' : 'bg-red-500'}`} />
                  <span className={`text-sm font-medium ${getStatusColor(site.status)}`}>
                    {site.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-gray-500 dark:text-gray-400 text-center py-8">
            No sites configured yet.
          </p>
        )}
      </div>
    </div>
  )
}

function StatCard({
  title,
  value,
  total,
  unit,
  icon,
  color,
  subtext,
  link,
}: {
  title: string
  value: number | string
  total?: number
  unit?: string
  icon: React.ReactNode
  color: 'blue' | 'green' | 'yellow' | 'red' | 'purple' | 'indigo'
  subtext?: string
  link?: string
}) {
  const colorClasses = {
    blue: 'bg-blue-100 dark:bg-blue-900 text-blue-600 dark:text-blue-400',
    green: 'bg-green-100 dark:bg-green-900 text-green-600 dark:text-green-400',
    yellow: 'bg-yellow-100 dark:bg-yellow-900 text-yellow-600 dark:text-yellow-400',
    red: 'bg-red-100 dark:bg-red-900 text-red-600 dark:text-red-400',
    purple: 'bg-purple-100 dark:bg-purple-900 text-purple-600 dark:text-purple-400',
    indigo: 'bg-indigo-100 dark:bg-indigo-900 text-indigo-600 dark:text-indigo-400',
  }

  const content = (
    <div className="card hover:shadow-lg transition-shadow">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-500 dark:text-gray-400">{title}</p>
          <div className="mt-2 flex items-baseline">
            <p className="text-3xl font-bold text-gray-900 dark:text-gray-100">
              {value}
              {unit && <span className="ml-1 text-lg font-normal text-gray-500">{unit}</span>}
            </p>
            {total !== undefined && (
              <span className="ml-2 text-sm text-gray-500 dark:text-gray-400">/ {total}</span>
            )}
          </div>
          {subtext && (
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">{subtext}</p>
          )}
        </div>
        <div className={`p-3 rounded-full ${colorClasses[color]}`}>
          {icon}
        </div>
      </div>
    </div>
  )

  if (link) {
    return <Link to={link}>{content}</Link>
  }

  return content
}

function MetricCard({
  title,
  value,
  subtext,
  icon,
  status,
}: {
  title: string
  value: string
  subtext?: string
  icon?: React.ReactNode
  status?: 'success' | 'warning' | 'danger'
}) {
  const statusColors = {
    success: 'text-green-600 dark:text-green-400',
    warning: 'text-yellow-600 dark:text-yellow-400',
    danger: 'text-red-600 dark:text-red-400',
  }

  return (
    <div className="card">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">{title}</h3>
        {icon && (
          <span className={status ? statusColors[status] : 'text-gray-400'}>
            {icon}
          </span>
        )}
      </div>
      <p className={`mt-2 text-2xl font-bold ${status ? statusColors[status] : 'text-gray-900 dark:text-gray-100'}`}>
        {value}
      </p>
      {subtext && (
        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">{subtext}</p>
      )}
    </div>
  )
}

function getEventColor(eventType: string): string {
  if (eventType.includes('delete') || eventType.includes('failed')) {
    return 'bg-red-500'
  }
  if (eventType.includes('create') || eventType.includes('login')) {
    return 'bg-green-500'
  }
  if (eventType.includes('update') || eventType.includes('change')) {
    return 'bg-blue-500'
  }
  return 'bg-gray-500'
}
