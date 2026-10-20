import { useEffect, useState } from 'react'
import { clusterView, ClusterView } from '../api'
import { Badge, Card, Empty, ErrorBanner, PageHeader } from './ui'

/** Live HA view: every node's role, term, leader and data generation. */
export default function Cluster() {
  const [view, setView] = useState<ClusterView | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [updated, setUpdated] = useState<Date | null>(null)

  useEffect(() => {
    let alive = true
    const tick = () =>
      clusterView()
        .then((v) => {
          if (!alive) return
          setView(v)
          setError(null)
          setUpdated(new Date())
        })
        .catch((e) => alive && setError(`Cluster status unavailable: ${e.message}`))
    tick()
    const t = setInterval(tick, 2000)
    return () => {
      alive = false
      clearInterval(t)
    }
  }, [])

  return (
    <div>
      <PageHeader title="Cluster" />
      <ErrorBanner error={error} />
      {view && !view.enabled && <Empty>This dashboard runs standalone (high availability is not configured).</Empty>}
      {view && view.enabled && (
        <>
          <Card className="mb-6">
            <div className="flex flex-wrap gap-8 text-sm">
              <div><div className="text-gray-500">Leader</div><div className="text-2xl font-bold">{view.leader_id ?? 'election in progress'}</div></div>
              <div><div className="text-gray-500">Term</div><div className="text-2xl font-bold">{view.term}</div></div>
              <div><div className="text-gray-500">Answered by</div><div className="text-2xl font-bold">{view.answered_by}</div></div>
              <div><div className="text-gray-500">Updated</div><div className="text-sm">{updated?.toLocaleTimeString()}</div></div>
            </div>
            <p className="mt-4 text-xs text-gray-500">
              Only the leader serves the API; followers forward requests to it and receive every change as a replicated
              snapshot. The generation counts replicated snapshots, so all reachable nodes should show the same value.
            </p>
          </Card>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            {view.nodes.map((n) => (
              <Card key={n.address}>
                <div className="flex items-center justify-between">
                  <div className="font-semibold text-gray-900">{n.status?.node_id ?? n.address}</div>
                  <Badge value={n.status ? n.status.role : 'unreachable'} />
                </div>
                <div className="text-xs text-gray-500 mb-3">{n.address}</div>
                {n.status ? (
                  <dl className="text-sm space-y-1">
                    <div className="flex justify-between"><dt className="text-gray-500">Term</dt><dd>{n.status.term}</dd></div>
                    <div className="flex justify-between"><dt className="text-gray-500">Sees leader</dt><dd>{n.status.leader_id ?? '—'}</dd></div>
                    <div className="flex justify-between"><dt className="text-gray-500">Data generation</dt><dd>{n.status.generation}</dd></div>
                    <div className="flex justify-between"><dt className="text-gray-500">Voted for</dt><dd>{n.status.voted_for ?? '—'}</dd></div>
                  </dl>
                ) : (
                  <p className="text-sm text-red-700">{n.error}</p>
                )}
              </Card>
            ))}
          </div>
        </>
      )}
    </div>
  )
}
