import { useQuery, gql } from '@apollo/client'
import { Shield, AlertTriangle, CheckCircle, XCircle } from 'lucide-react'
import clsx from 'clsx'

const SECURITY_QUERY = gql`
  query Security {
    securityEvents {
      id
      timestamp
      severity
      type
      source
      destination
      description
      blocked
    }
    threatStats {
      total
      blocked
      allowed
      byType {
        type
        count
      }
    }
  }
`

interface SecurityEvent {
  id: string
  timestamp: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  type: string
  source: string
  destination: string
  description: string
  blocked: boolean
}

interface ThreatStats {
  total: number
  blocked: number
  allowed: number
  byType: Array<{
    type: string
    count: number
  }>
}

interface SecurityData {
  securityEvents: SecurityEvent[]
  threatStats: ThreatStats
}

export default function Security() {
  const { loading, error, data } = useQuery<SecurityData>(SECURITY_QUERY, {
    pollInterval: 5000,
  })

  if (loading) return <div>Loading security data...</div>
  if (error) return <div>Error: {error.message}</div>
  if (!data) return <div>No data</div>

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-red-600 bg-red-50 border-red-200'
      case 'high':
        return 'text-orange-600 bg-orange-50 border-orange-200'
      case 'medium':
        return 'text-yellow-600 bg-yellow-50 border-yellow-200'
      case 'low':
        return 'text-blue-600 bg-blue-50 border-blue-200'
      default:
        return 'text-gray-600 bg-gray-50 border-gray-200'
    }
  }

  const blockRate = data.threatStats.total > 0
    ? (data.threatStats.blocked / data.threatStats.total) * 100
    : 0

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-gray-900">Security</h1>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 gap-6 sm:grid-cols-3">
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Total Threats</p>
              <p className="mt-2 text-3xl font-semibold text-gray-900">
                {data.threatStats.total.toLocaleString()}
              </p>
            </div>
            <div className="rounded-full p-3 bg-gray-50">
              <Shield className="h-6 w-6 text-gray-600" />
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Blocked</p>
              <p className="mt-2 text-3xl font-semibold text-green-600">
                {data.threatStats.blocked.toLocaleString()}
              </p>
            </div>
            <div className="rounded-full p-3 bg-green-50">
              <CheckCircle className="h-6 w-6 text-green-600" />
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Block Rate</p>
              <p className="mt-2 text-3xl font-semibold text-gray-900">
                {blockRate.toFixed(1)}%
              </p>
            </div>
            <div className="rounded-full p-3 bg-primary-50">
              <Shield className="h-6 w-6 text-primary-600" />
            </div>
          </div>
        </div>
      </div>

      {/* Threat Types */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">
          Threats by Type
        </h2>
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {data.threatStats.byType.map((item) => (
            <div key={item.type} className="border border-gray-200 rounded-lg p-4">
              <p className="text-sm text-gray-600">{item.type}</p>
              <p className="mt-1 text-2xl font-bold text-gray-900">
                {item.count.toLocaleString()}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* Security Events */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">Recent Events</h2>
        </div>
        <div className="divide-y divide-gray-200">
          {data.securityEvents.length === 0 ? (
            <div className="px-6 py-8 text-center text-gray-500">
              No security events
            </div>
          ) : (
            data.securityEvents.map((event) => (
              <div key={event.id} className="px-6 py-4 hover:bg-gray-50">
                <div className="flex items-start gap-4">
                  <div className={clsx(
                    'flex-shrink-0 p-2 rounded-lg border',
                    getSeverityColor(event.severity)
                  )}>
                    <AlertTriangle className="h-5 w-5" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 mb-1">
                      <span className={clsx(
                        'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border',
                        getSeverityColor(event.severity)
                      )}>
                        {event.severity}
                      </span>
                      <span className="text-sm font-medium text-gray-900">
                        {event.type}
                      </span>
                      {event.blocked ? (
                        <span className="inline-flex items-center gap-1 text-xs text-green-600">
                          <CheckCircle className="h-3 w-3" />
                          Blocked
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs text-red-600">
                          <XCircle className="h-3 w-3" />
                          Allowed
                        </span>
                      )}
                    </div>
                    <p className="text-sm text-gray-900 mb-1">
                      {event.description}
                    </p>
                    <p className="text-xs text-gray-500">
                      {event.source} → {event.destination} • {new Date(event.timestamp).toLocaleString()}
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
