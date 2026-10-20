import { useMutation, useQuery } from '@apollo/client'
import { CHECK_PATH, FAILOVER_PATH, PATHS } from '../graphql/operations'
import { Badge, Button, Empty, ErrorBanner, PageHeader, fmtDate, fmtNum } from './ui'

interface Path {
  id: string
  sourceSiteId: string
  destinationSiteId: string
  latencyMs: number
  packetLoss: number
  bandwidthMbps: number
  qualityScore: number
  status: string
  lastUpdated: string
}

export default function Paths() {
  const { data, error, loading, refetch } = useQuery<{ paths: Path[]; sites: { id: string; name: string }[] }>(PATHS, {
    pollInterval: 15000,
  })
  const [checkPath, checked] = useMutation(CHECK_PATH)
  const [failoverPath, failed] = useMutation(FAILOVER_PATH)
  const siteName = (id: string) => data?.sites.find((s) => s.id === id)?.name ?? id

  return (
    <div>
      <PageHeader title="Paths">
        <Button variant="secondary" onClick={() => refetch()}>Refresh</Button>
      </PageHeader>
      <ErrorBanner error={error ?? checked.error ?? failed.error} />
      {loading && !data && <p className="text-gray-500">Loading…</p>}
      {data && data.paths.length === 0 && (
        <Empty>
          No paths yet. Paths between sites are discovered by the SD-WAN peering engine once sites have endpoints;
          they appear here with live latency, loss and quality.
        </Empty>
      )}
      {data && data.paths.length > 0 && (
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200 text-sm">
            <thead className="bg-gray-50 text-left text-gray-500">
              <tr>
                <th className="px-4 py-2">Path</th>
                <th className="px-4 py-2">Status</th>
                <th className="px-4 py-2">Latency</th>
                <th className="px-4 py-2">Loss</th>
                <th className="px-4 py-2">Bandwidth</th>
                <th className="px-4 py-2">Quality</th>
                <th className="px-4 py-2">Updated</th>
                <th className="px-4 py-2" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {data.paths.map((p) => (
                <tr key={p.id}>
                  <td className="px-4 py-2 font-medium text-gray-900">
                    {siteName(p.sourceSiteId)} → {siteName(p.destinationSiteId)}
                    <div className="text-xs text-gray-400">#{p.id}</div>
                  </td>
                  <td className="px-4 py-2"><Badge value={p.status} /></td>
                  <td className="px-4 py-2">{fmtNum(p.latencyMs)} ms</td>
                  <td className="px-4 py-2">{fmtNum(p.packetLoss, 2)} %</td>
                  <td className="px-4 py-2">{fmtNum(p.bandwidthMbps)} Mbps</td>
                  <td className="px-4 py-2">{fmtNum(p.qualityScore, 0)}</td>
                  <td className="px-4 py-2 text-gray-500">{fmtDate(p.lastUpdated)}</td>
                  <td className="px-4 py-2 text-right space-x-2 whitespace-nowrap">
                    <Button variant="secondary" onClick={() => checkPath({ variables: { pathId: p.id } }).then(() => refetch())}>
                      Check health
                    </Button>
                    <Button
                      variant="danger"
                      onClick={() => {
                        if (confirm('Mark this path down and fail traffic over to the next best path?'))
                          failoverPath({ variables: { pathId: p.id } }).then(() => refetch())
                      }}
                    >
                      Fail over
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
