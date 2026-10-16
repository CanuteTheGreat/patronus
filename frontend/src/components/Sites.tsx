import { useState, FormEvent } from 'react'
import { useMutation, useQuery, gql } from '@apollo/client'
import { MapPin, Activity, AlertCircle, Plus, Trash2 } from 'lucide-react'
import clsx from 'clsx'
import { getUser } from '../auth'

// Field names match the dashboard's real GraphQL schema (GqlSite in
// crates/patronus-dashboard/src/graphql/types.rs); the dashboard crate's
// tests/frontend_contract.rs validates these documents against that schema
// in CI. (The previous query asked for uptime/lastSeen/links/metrics, which
// the API has never had, so this page could only ever show an error.)
const SITES_QUERY = gql`
  query Sites {
    sites {
      id
      name
      location
      status
      endpointCount
      createdAt
      updatedAt
    }
  }
`

const CREATE_SITE = gql`
  mutation CreateSite($input: CreateSiteInput!) {
    createSite(input: $input) {
      id
      name
    }
  }
`

const DELETE_SITE = gql`
  mutation DeleteSite($id: String!) {
    deleteSite(id: $id)
  }
`

interface Site {
  id: string
  name: string
  location: string | null
  status: 'ACTIVE' | 'DEGRADED' | 'OFFLINE' | 'MAINTENANCE'
  endpointCount: number
  createdAt: string
  updatedAt: string
}

interface SitesData {
  sites: Site[]
}

const statusColor: Record<string, string> = {
  ACTIVE: 'text-green-600 bg-green-50',
  DEGRADED: 'text-yellow-600 bg-yellow-50',
  OFFLINE: 'text-red-600 bg-red-50',
  MAINTENANCE: 'text-gray-600 bg-gray-50',
}

export default function Sites() {
  const { loading, error, data, refetch } = useQuery<SitesData>(SITES_QUERY, {
    pollInterval: 5000,
  })
  const [createSite, createState] = useMutation(CREATE_SITE)
  const [deleteSite, deleteState] = useMutation(DELETE_SITE)
  const [name, setName] = useState('')
  const [location, setLocation] = useState('')
  const role = getUser()?.role
  const canWrite = role === 'admin' || role === 'operator'
  const canDelete = role === 'admin'

  async function onCreate(e: FormEvent) {
    e.preventDefault()
    await createSite({ variables: { input: { name, location: location || null } } })
    setName('')
    setLocation('')
    refetch()
  }

  async function onDelete(site: Site) {
    if (!window.confirm(`Delete site "${site.name}"? Its paths are removed too.`)) return
    await deleteSite({ variables: { id: site.id } })
    refetch()
  }

  if (loading && !data) return <div>Loading sites...</div>
  if (error) return <div role="alert">Error: {error.message}</div>
  if (!data) return <div>No data</div>

  const mutationError = createState.error?.message ?? deleteState.error?.message

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">Sites</h1>
        <div className="text-sm text-gray-600" data-testid="site-count">
          Total: {data.sites.length} sites
        </div>
      </div>

      {canWrite && (
        <form onSubmit={onCreate} className="flex flex-wrap items-end gap-3 rounded-lg bg-white p-4 shadow" aria-label="Add site">
          <div>
            <label htmlFor="site-name" className="block text-xs text-gray-600">Name</label>
            <input id="site-name" required value={name} onChange={(e) => setName(e.target.value)}
              className="mt-1 rounded border border-gray-300 px-3 py-2" />
          </div>
          <div>
            <label htmlFor="site-location" className="block text-xs text-gray-600">Location</label>
            <input id="site-location" value={location} onChange={(e) => setLocation(e.target.value)}
              className="mt-1 rounded border border-gray-300 px-3 py-2" />
          </div>
          <button type="submit" disabled={createState.loading}
            className="inline-flex items-center gap-1 rounded bg-primary-600 px-4 py-2 text-white hover:bg-primary-700 disabled:opacity-50">
            <Plus className="h-4 w-4" /> Add site
          </button>
          {mutationError && <p role="alert" className="w-full text-sm text-red-600">{mutationError}</p>}
        </form>
      )}

      {data.sites.length === 0 && (
        <p className="text-gray-600">No sites yet.{canWrite ? ' Add the first one above.' : ''}</p>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {data.sites.map((site) => (
          <div key={site.id} className="bg-white rounded-lg shadow p-6" data-testid="site-card">
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-primary-50 rounded-lg">
                  <MapPin className="h-6 w-6 text-primary-600" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-gray-900">{site.name}</h3>
                  <p className="text-sm text-gray-600">{site.location ?? 'No location'}</p>
                </div>
              </div>
              <span className={clsx(
                'inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium',
                statusColor[site.status] ?? 'text-gray-600 bg-gray-50',
              )}>
                {site.status === 'ACTIVE' ? <Activity className="h-3 w-3" /> : <AlertCircle className="h-3 w-3" />}
                {site.status.toLowerCase()}
              </span>
            </div>

            <div className="grid grid-cols-2 gap-4 mb-4">
              <div>
                <p className="text-xs text-gray-600">Endpoints</p>
                <p className="text-lg font-semibold text-gray-900">{site.endpointCount}</p>
              </div>
              <div>
                <p className="text-xs text-gray-600">Site ID</p>
                <p className="truncate font-mono text-xs text-gray-700" title={site.id}>{site.id}</p>
              </div>
            </div>

            <div className="flex items-center justify-between pt-4 border-t border-gray-200">
              <p className="text-xs text-gray-600">
                Updated: {new Date(site.updatedAt).toLocaleString()}
              </p>
              {canDelete && (
                <button type="button" onClick={() => onDelete(site)}
                  className="inline-flex items-center gap-1 text-sm text-red-600 hover:text-red-800"
                  aria-label={`Delete site ${site.name}`}>
                  <Trash2 className="h-4 w-4" /> Delete
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
