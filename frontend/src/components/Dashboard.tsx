import { useQuery, gql } from '@apollo/client'
import { Activity, AlertTriangle, CheckCircle, Clock } from 'lucide-react'
import MetricsChart from './MetricsChart'
import TopologyPreview from './TopologyPreview'

const DASHBOARD_QUERY = gql`
  query Dashboard {
    overview {
      totalSites
      activeSites
      totalLinks
      healthyLinks
      avgLatency
      totalThroughput
      packetLoss
    }
    recentAlerts {
      id
      severity
      message
      timestamp
      siteId
    }
    linkMetrics {
      timestamp
      throughput
      latency
      packetLoss
    }
  }
`

interface DashboardData {
  overview: {
    totalSites: number
    activeSites: number
    totalLinks: number
    healthyLinks: number
    avgLatency: number
    totalThroughput: number
    packetLoss: number
  }
  recentAlerts: Array<{
    id: string
    severity: 'critical' | 'warning' | 'info'
    message: string
    timestamp: string
    siteId: string
  }>
  linkMetrics: Array<{
    timestamp: string
    throughput: number
    latency: number
    packetLoss: number
  }>
}

export default function Dashboard() {
  const { loading, error, data } = useQuery<DashboardData>(DASHBOARD_QUERY, {
    pollInterval: 5000,
  })

  if (loading) return <div>Loading...</div>
  if (error) return <div>Error: {error.message}</div>
  if (!data) return <div>No data</div>

  const { overview, recentAlerts, linkMetrics } = data

  const stats = [
    {
      name: 'Active Sites',
      value: `${overview.activeSites}/${overview.totalSites}`,
      icon: Activity,
      color: 'text-green-600',
      bgColor: 'bg-green-50',
    },
    {
      name: 'Healthy Links',
      value: `${overview.healthyLinks}/${overview.totalLinks}`,
      icon: CheckCircle,
      color: 'text-blue-600',
      bgColor: 'bg-blue-50',
    },
    {
      name: 'Avg Latency',
      value: `${overview.avgLatency.toFixed(1)}ms`,
      icon: Clock,
      color: 'text-yellow-600',
      bgColor: 'bg-yellow-50',
    },
    {
      name: 'Packet Loss',
      value: `${(overview.packetLoss * 100).toFixed(2)}%`,
      icon: AlertTriangle,
      color: overview.packetLoss > 0.01 ? 'text-red-600' : 'text-green-600',
      bgColor: overview.packetLoss > 0.01 ? 'bg-red-50' : 'bg-green-50',
    },
  ]

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
        {stats.map((stat) => (
          <div key={stat.name} className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">{stat.name}</p>
                <p className="mt-2 text-3xl font-semibold text-gray-900">
                  {stat.value}
                </p>
              </div>
              <div className={`rounded-full p-3 ${stat.bgColor}`}>
                <stat.icon className={`h-6 w-6 ${stat.color}`} />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Charts and Topology */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">
            Network Performance
          </h2>
          <MetricsChart data={linkMetrics} />
        </div>
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">
            Network Topology
          </h2>
          <TopologyPreview />
        </div>
      </div>

      {/* Recent Alerts */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">Recent Alerts</h2>
        </div>
        <div className="divide-y divide-gray-200">
          {recentAlerts.length === 0 ? (
            <div className="px-6 py-8 text-center text-gray-500">
              No recent alerts
            </div>
          ) : (
            recentAlerts.map((alert) => (
              <div key={alert.id} className="px-6 py-4 hover:bg-gray-50">
                <div className="flex items-center gap-3">
                  <AlertTriangle
                    className={
                      alert.severity === 'critical'
                        ? 'h-5 w-5 text-red-600'
                        : alert.severity === 'warning'
                        ? 'h-5 w-5 text-yellow-600'
                        : 'h-5 w-5 text-blue-600'
                    }
                  />
                  <div className="flex-1">
                    <p className="text-sm font-medium text-gray-900">
                      {alert.message}
                    </p>
                    <p className="text-xs text-gray-500">
                      Site: {alert.siteId} • {new Date(alert.timestamp).toLocaleString()}
                    </p>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
