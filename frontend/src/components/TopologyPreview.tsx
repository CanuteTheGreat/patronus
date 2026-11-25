import { gql, useQuery } from '@apollo/client'
import { Link } from 'react-router-dom'
import { ArrowRight } from 'lucide-react'

const PREVIEW_QUERY = gql`
  query TopologyPreview {
    sites {
      id
      name
      status
    }
    links {
      id
      status
    }
  }
`

interface PreviewData {
  sites: Array<{ id: string; name: string; status: string }>
  links: Array<{ id: string; status: string }>
}

const dot: Record<string, string> = {
  active: 'bg-green-500',
  degraded: 'bg-yellow-500',
  down: 'bg-red-500',
  inactive: 'bg-red-500',
}

export default function TopologyPreview() {
  const { data, loading } = useQuery<PreviewData>(PREVIEW_QUERY, { pollInterval: 15000 })
  const sites = data?.sites ?? []
  const links = data?.links ?? []
  const up = links.filter((l) => l.status.toLowerCase() === 'active').length

  return (
    <div data-testid="topology-preview" className="flex flex-col justify-between min-h-64 gap-4">
      {loading && !data ? (
        <p className="text-gray-500 dark:text-gray-400">Loading…</p>
      ) : sites.length === 0 ? (
        <p className="text-gray-500 dark:text-gray-400">
          No sites yet. Add your first site and it appears here with its links.
        </p>
      ) : (
        <>
          <p className="text-sm text-gray-700 dark:text-gray-300" data-testid="topology-counts">
            {sites.length} {sites.length === 1 ? 'site' : 'sites'}, {up} of {links.length}{' '}
            {links.length === 1 ? 'link' : 'links'} up
          </p>
          <ul className="space-y-2">
            {sites.slice(0, 6).map((s) => (
              <li key={s.id} className="flex items-center gap-2 text-sm text-gray-900 dark:text-gray-100">
                <span
                  className={`inline-block h-3 w-3 rounded-full ${dot[s.status.toLowerCase()] ?? 'bg-gray-400'}`}
                  aria-hidden="true"
                />
                <span>{s.name}</span>
                <span className="text-gray-500 dark:text-gray-400">({s.status.toLowerCase()})</span>
              </li>
            ))}
            {sites.length > 6 && (
              <li className="text-sm text-gray-500 dark:text-gray-400">and {sites.length - 6} more</li>
            )}
          </ul>
        </>
      )}
      <Link
        to={sites.length === 0 && !loading ? '/sites' : '/topology'}
        className="inline-flex items-center gap-2 self-start px-4 py-2 bg-primary-700 text-white rounded-lg hover:bg-primary-800 transition-colors"
      >
        {sites.length === 0 && !loading ? 'Add a site' : 'Open topology'}
        <ArrowRight className="h-4 w-4" />
      </Link>
    </div>
  )
}
