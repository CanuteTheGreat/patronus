import { useQuery } from '@apollo/client'
import { AUDIT_LOGS } from '../graphql/operations'
import { currentUser } from '../api'
import { Empty, ErrorBanner, PageHeader, fmtDate } from './ui'

interface AuditLog {
  id: string
  userId: string
  eventType: string
  description: string
  ipAddress: string
  timestamp: string
  metadata: string | null
}

export default function Security() {
  const isAdmin = currentUser()?.role?.toLowerCase() === 'admin'
  const { data, error, loading } = useQuery<{ auditLogs: AuditLog[] }>(AUDIT_LOGS, {
    variables: { limit: 200 },
    pollInterval: 15000,
    skip: !isAdmin,
  })

  return (
    <div>
      <PageHeader title="Security audit log" />
      {!isAdmin && <Empty>The audit log is visible to administrators only.</Empty>}
      <ErrorBanner error={error} />
      {loading && !data && <p className="text-gray-500">Loading…</p>}
      {data && data.auditLogs.length === 0 && <Empty>No audit events yet.</Empty>}
      {data && data.auditLogs.length > 0 && (
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200 text-sm">
            <thead className="bg-gray-50 text-left text-gray-500">
              <tr>
                <th className="px-4 py-2">Time</th>
                <th className="px-4 py-2">Event</th>
                <th className="px-4 py-2">Description</th>
                <th className="px-4 py-2">User</th>
                <th className="px-4 py-2">IP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {data.auditLogs.map((l) => (
                <tr key={l.id}>
                  <td className="px-4 py-2 whitespace-nowrap text-gray-500">{fmtDate(l.timestamp)}</td>
                  <td className="px-4 py-2 font-medium">{l.eventType}</td>
                  <td className="px-4 py-2">{l.description}</td>
                  <td className="px-4 py-2 font-mono text-xs">{l.userId}</td>
                  <td className="px-4 py-2 font-mono text-xs">{l.ipAddress}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
