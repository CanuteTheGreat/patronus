import { useEffect, useState } from 'react'
import { Crown, Server, WifiOff } from 'lucide-react'
import clsx from 'clsx'
import { ClusterView, fetchCluster } from '../cluster'

export function useCluster(intervalMs = 3000) {
  const [view, setView] = useState<ClusterView | null>(null)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    let alive = true
    const load = () =>
      fetchCluster()
        .then((v) => { if (alive) { setView(v); setError(null) } })
        .catch((e) => { if (alive) setError(String(e)) })
    load()
    const t = setInterval(load, intervalMs)
    return () => { alive = false; clearInterval(t) }
  }, [intervalMs])
  return { view, error }
}

/** Compact header badge: which node leads the HA cluster. */
export function LeaderBadge() {
  const { view } = useCluster(5000)
  if (!view) return null
  if (!view.ha_enabled) {
    return <span className="text-xs text-gray-500 dark:text-gray-400" data-testid="leader-badge">Single node</span>
  }
  return (
    <span data-testid="leader-badge"
      className={clsx('inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium',
        view.leader_id ? 'bg-green-100 dark:bg-green-900/40 text-green-800 dark:text-green-200' : 'bg-red-100 dark:bg-red-900/40 text-red-800 dark:text-red-200')}>
      <Crown className="h-3 w-3" />
      {view.leader_id ? `Leader: ${view.leader_id} (term ${view.term})` : 'No leader'}
    </span>
  )
}

export default function Cluster() {
  const { view, error } = useCluster()

  if (error && !view) return <div role="alert">Cannot load cluster status: {error}</div>
  if (!view) return <div>Loading cluster status...</div>

  return (
    <div>
      <h2 className="mb-2 text-2xl font-bold text-gray-900 dark:text-gray-100">High-Availability Cluster</h2>
      {!view.ha_enabled ? (
        <p className="text-gray-600 dark:text-gray-300">This dashboard runs as a single node (HA is not configured).</p>
      ) : (
        <>
          <p className="mb-6 text-gray-600 dark:text-gray-300">
            Leader: <strong data-testid="cluster-leader">{view.leader_id ?? 'none elected'}</strong> &middot; term {view.term}
          </p>
          <div className="overflow-x-auto rounded-lg">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700 rounded-lg bg-white dark:bg-gray-800 shadow">
            <thead className="bg-gray-50 dark:bg-gray-900 text-left text-xs uppercase text-gray-500 dark:text-gray-400">
              <tr>
                <th className="px-4 py-3">Node</th>
                <th className="px-4 py-3">Role</th>
                <th className="px-4 py-3">Term</th>
                <th className="px-4 py-3">Log / committed / applied</th>
                <th className="px-4 py-3">Address</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 dark:divide-gray-700 text-sm">
              {view.members.map((m) => {
                const s = m.status
                const isLeader = s?.role === 'Leader'
                return (
                  <tr key={m.addr || 'self'} data-testid="cluster-member" className={clsx(isLeader && 'bg-green-50 dark:bg-green-900/30')}>
                    <td className="px-4 py-3 font-medium">
                      <span className="inline-flex items-center gap-2">
                        {m.reachable ? <Server className="h-4 w-4" /> : <WifiOff className="h-4 w-4 text-red-500 dark:text-red-400" />}
                        {s?.node_id ?? m.addr}
                        {m.is_self && <span className="text-xs text-gray-500 dark:text-gray-400">(serving this page)</span>}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      {m.reachable ? (
                        <span className={clsx('inline-flex items-center gap-1', isLeader ? 'font-semibold text-green-700 dark:text-green-300' : 'text-gray-700 dark:text-gray-300')}>
                          {isLeader && <Crown className="h-4 w-4" />}{s?.role}
                        </span>
                      ) : (
                        <span className="text-red-700 dark:text-red-400">Unreachable</span>
                      )}
                    </td>
                    <td className="px-4 py-3">{s?.term ?? '-'}</td>
                    <td className="px-4 py-3">{s ? `${s.log_index} / ${s.commit_index} / ${s.applied_index}` : '-'}</td>
                    <td className="px-4 py-3 text-gray-500 dark:text-gray-400">{m.addr || 'local'}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
          </div>
        </>
      )}
    </div>
  )
}
