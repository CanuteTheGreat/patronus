import { useQuery, gql } from '@apollo/client'
import { Target, TrendingUp, TrendingDown } from 'lucide-react'
import clsx from 'clsx'

const SLA_QUERY = gql`
  query SLA {
    slaPolicies {
      id
      name
      description
      targetLatency
      targetPacketLoss
      targetAvailability
      currentLatency
      currentPacketLoss
      currentAvailability
      compliance
      violations
    }
  }
`

interface SLAPolicy {
  id: string
  name: string
  description: string
  targetLatency: number
  targetPacketLoss: number
  targetAvailability: number
  currentLatency: number
  currentPacketLoss: number
  currentAvailability: number
  compliance: number
  violations: number
}

interface SLAData {
  slaPolicies: SLAPolicy[]
}

export default function SLA() {
  const { loading, error, data } = useQuery<SLAData>(SLA_QUERY, {
    pollInterval: 5000,
  })

  if (loading) return <div>Loading SLA policies...</div>
  if (error) return <div>Error: {error.message}</div>
  if (!data) return <div>No data</div>

  const getComplianceColor = (compliance: number) => {
    if (compliance >= 99) return 'text-green-600'
    if (compliance >= 95) return 'text-yellow-600'
    return 'text-red-600'
  }

  const getComplianceBgColor = (compliance: number) => {
    if (compliance >= 99) return 'bg-green-50'
    if (compliance >= 95) return 'bg-yellow-50'
    return 'bg-red-50'
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">SLA Compliance</h1>
        <div className="text-sm text-gray-600">
          {data.slaPolicies.length} policies
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6">
        {data.slaPolicies.map((policy) => (
          <div key={policy.id} className="bg-white rounded-lg shadow p-6">
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className={clsx('p-2 rounded-lg', getComplianceBgColor(policy.compliance))}>
                  <Target className={clsx('h-6 w-6', getComplianceColor(policy.compliance))} />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-gray-900">
                    {policy.name}
                  </h3>
                  <p className="text-sm text-gray-600">{policy.description}</p>
                </div>
              </div>
              <div className="text-right">
                <p className="text-3xl font-bold text-gray-900">
                  {policy.compliance.toFixed(1)}%
                </p>
                <p className="text-xs text-gray-600">Compliance</p>
              </div>
            </div>

            <div className="grid grid-cols-3 gap-4 mb-4">
              {/* Latency */}
              <div className="border border-gray-200 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <p className="text-sm font-medium text-gray-700">Latency</p>
                  {policy.currentLatency <= policy.targetLatency ? (
                    <TrendingDown className="h-4 w-4 text-green-600" />
                  ) : (
                    <TrendingUp className="h-4 w-4 text-red-600" />
                  )}
                </div>
                <p className="text-2xl font-bold text-gray-900">
                  {policy.currentLatency.toFixed(1)}ms
                </p>
                <p className="text-xs text-gray-600">
                  Target: {policy.targetLatency}ms
                </p>
              </div>

              {/* Packet Loss */}
              <div className="border border-gray-200 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <p className="text-sm font-medium text-gray-700">Packet Loss</p>
                  {policy.currentPacketLoss <= policy.targetPacketLoss ? (
                    <TrendingDown className="h-4 w-4 text-green-600" />
                  ) : (
                    <TrendingUp className="h-4 w-4 text-red-600" />
                  )}
                </div>
                <p className="text-2xl font-bold text-gray-900">
                  {(policy.currentPacketLoss * 100).toFixed(3)}%
                </p>
                <p className="text-xs text-gray-600">
                  Target: {(policy.targetPacketLoss * 100).toFixed(3)}%
                </p>
              </div>

              {/* Availability */}
              <div className="border border-gray-200 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <p className="text-sm font-medium text-gray-700">Availability</p>
                  {policy.currentAvailability >= policy.targetAvailability ? (
                    <TrendingUp className="h-4 w-4 text-green-600" />
                  ) : (
                    <TrendingDown className="h-4 w-4 text-red-600" />
                  )}
                </div>
                <p className="text-2xl font-bold text-gray-900">
                  {(policy.currentAvailability * 100).toFixed(2)}%
                </p>
                <p className="text-xs text-gray-600">
                  Target: {(policy.targetAvailability * 100).toFixed(2)}%
                </p>
              </div>
            </div>

            {policy.violations > 0 && (
              <div className="bg-red-50 border border-red-200 rounded-lg p-3">
                <p className="text-sm text-red-800">
                  <span className="font-semibold">{policy.violations}</span> violations in the last 24 hours
                </p>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
