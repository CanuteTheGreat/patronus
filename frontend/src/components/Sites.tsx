import { FormEvent, useState } from 'react'
import { useMutation, useQuery } from '@apollo/client'
import { CREATE_SITE, DELETE_SITE, SITES, UPDATE_SITE } from '../graphql/operations'
import { Badge, Button, Card, Empty, ErrorBanner, Field, PageHeader, fmtDate, inputClass } from './ui'

interface Site {
  id: string
  name: string
  location: string | null
  endpointCount: number
  status: string
  createdAt: string
  updatedAt: string
}

const STATUSES = ['ACTIVE', 'DEGRADED', 'OFFLINE', 'MAINTENANCE']

export default function Sites() {
  const { data, error, loading, refetch } = useQuery<{ sites: Site[] }>(SITES)
  const [name, setName] = useState('')
  const [location, setLocation] = useState('')
  const [createSite, created] = useMutation(CREATE_SITE)
  const [updateSite, updated] = useMutation(UPDATE_SITE)
  const [deleteSite, deleted] = useMutation(DELETE_SITE)
  const mutationError = created.error ?? updated.error ?? deleted.error

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    await createSite({ variables: { input: { name, location: location || null } } })
    setName('')
    setLocation('')
    refetch()
  }

  return (
    <div>
      <PageHeader title="Sites" />
      <ErrorBanner error={error ?? mutationError} />
      <Card title="Add a site" className="mb-6">
        <form onSubmit={submit} className="grid grid-cols-1 gap-4 sm:grid-cols-3 items-end">
          <Field label="Name">
            <input className={inputClass} value={name} onChange={(e) => setName(e.target.value)} required />
          </Field>
          <Field label="Location">
            <input className={inputClass} value={location} onChange={(e) => setLocation(e.target.value)} placeholder="optional" />
          </Field>
          <Button type="submit" disabled={created.loading}>Add site</Button>
        </form>
      </Card>
      {loading && !data && <p className="text-gray-500">Loading…</p>}
      {data && data.sites.length === 0 && <Empty>No sites yet. Add one above.</Empty>}
      {data && data.sites.length > 0 && (
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200 text-sm">
            <thead className="bg-gray-50 text-left text-gray-500">
              <tr>
                <th className="px-4 py-2">Name</th>
                <th className="px-4 py-2">Location</th>
                <th className="px-4 py-2">Endpoints</th>
                <th className="px-4 py-2">Status</th>
                <th className="px-4 py-2">Updated</th>
                <th className="px-4 py-2" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {data.sites.map((s) => (
                <tr key={s.id}>
                  <td className="px-4 py-2 font-medium text-gray-900">{s.name}</td>
                  <td className="px-4 py-2">{s.location ?? '—'}</td>
                  <td className="px-4 py-2">{s.endpointCount}</td>
                  <td className="px-4 py-2">
                    <div className="flex items-center gap-2">
                      <Badge value={s.status} />
                      <select
                        aria-label={`Set status of ${s.name}`}
                        className="text-xs border border-gray-300 rounded"
                        value={s.status}
                        onChange={(e) => updateSite({ variables: { input: { id: s.id, status: e.target.value } } }).then(() => refetch())}
                      >
                        {STATUSES.map((st) => (
                          <option key={st} value={st}>{st}</option>
                        ))}
                      </select>
                    </div>
                  </td>
                  <td className="px-4 py-2 text-gray-500">{fmtDate(s.updatedAt)}</td>
                  <td className="px-4 py-2 text-right">
                    <Button
                      variant="danger"
                      onClick={() => {
                        if (confirm(`Delete site ${s.name}?`)) deleteSite({ variables: { id: s.id } }).then(() => refetch())
                      }}
                    >
                      Delete
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
