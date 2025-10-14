import { useQuery, gql } from '@apollo/client'
import { MapPin, Activity, AlertCircle } from 'lucide-react'
import clsx from 'clsx'

const SITES_QUERY = gql`
  query Sites {
    sites {
      id
      name
      location
      status
      uptime
      lastSeen
      links {
        id
        targetId
        status
      }
      metrics {
        throughput
        latency
        packetLoss
      }
    }
  }
`

interface Site {
  id: string
  name: string
  location: string
  status: 'active' | 'inactive' | 'degraded'
  uptime: number
  lastSeen: string
  links: Array<{
    id: string
    targetId: string
    status: string
  }>
  metrics: {
    throughput: number
    latency: number
    packetLoss: number
  }
}

interface SitesData {
  sites: Site[]
}

export default function Sites() {
  const { loading, error, data } = useQuery<SitesData>(SITES_QUERY, {
    pollInterval: 5000,
  })

  if (loading) return <div>Loading sites...</div>
  if (error) return <div>Error: {error.message}</div>
  if (!data) return <div>No data</div>

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'text-green-600 bg-green-50'
      case 'degraded':
        return 'text-yellow-600 bg-yellow-50'
      case 'inactive':
        return 'text-red-600 bg-red-50'
      default:
        return 'text-gray-600 bg-gray-50'
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">Sites</h1>
        <div className="text-sm text-gray-600">
          Total: {data.sites.length} sites
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {data.sites.map((site) => (
          <div key={site.id} className="bg-white rounded-lg shadow p-6">
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-primary-50 rounded-lg">
                  <MapPin className="h-6 w-6 text-primary-600" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-gray-900">
                    {site.name}
                  </h3>
                  <p className="text-sm text-gray-600">{site.location}</p>
                </div>
              </div>
              <span
                className={clsx(
                  'inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium',
                  getStatusColor(site.status)
                )}
              >
                {site.status === 'active' && <Activity className="h-3 w-3" />}
                {site.status !== 'active' && <AlertCircle className="h-3 w-3" />}
                {site.status}
              </span>
            </div>

            <div className="grid grid-cols-2 gap-4 mb-4">
              <div>
                <p className="text-xs text-gray-600">Uptime</p>
                <p className="text-lg font-semibold text-gray-900">
                  {(site.uptime * 100).toFixed(2)}%
                </p>
              </div>
              <div>
                <p className="text-xs text-gray-600">Links</p>
                <p className="text-lg font-semibold text-gray-900">
                  {site.links.length}
                </p>
              </div>
              <div>
                <p className="text-xs text-gray-600">Latency</p>
                <p className="text-lg font-semibold text-gray-900">
                  {site.metrics.latency.toFixed(1)}ms
                </p>
              </div>
              <div>
                <p className="text-xs text-gray-600">Packet Loss</p>
                <p className="text-lg font-semibold text-gray-900">
                  {(site.metrics.packetLoss * 100).toFixed(2)}%
                </p>
              </div>
            </div>

            <div className="pt-4 border-t border-gray-200">
              <p className="text-xs text-gray-600">
                Last seen: {new Date(site.lastSeen).toLocaleString()}
              </p>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
