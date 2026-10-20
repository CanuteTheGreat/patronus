import { FormEvent, useState } from 'react'
import { useMutation, useQuery } from '@apollo/client'
import { CREATE_POLICY, DELETE_POLICY, POLICIES, TOGGLE_POLICY } from '../graphql/operations'
import { Button, Card, Empty, ErrorBanner, Field, PageHeader, fmtDate, inputClass } from './ui'

interface Policy {
  id: string
  name: string
  description: string | null
  priority: number
  matchRules: string
  action: string
  enabled: boolean
  packetsMatched: number
  bytesMatched: number
  createdAt: string
}

const ACTIONS = ['ALLOW', 'DENY', 'ROUTE', 'QOS']
const EXAMPLE_RULES = '{"dst_port_range": [443, 443], "protocol": 6}'

export default function Policies() {
  const { data, error, loading, refetch } = useQuery<{ policies: Policy[] }>(POLICIES, { pollInterval: 15000 })
  const [createPolicy, created] = useMutation(CREATE_POLICY)
  const [togglePolicy, toggled] = useMutation(TOGGLE_POLICY)
  const [deletePolicy, deleted] = useMutation(DELETE_POLICY)
  const [form, setForm] = useState({ name: '', description: '', priority: 100, action: 'ALLOW', matchRules: EXAMPLE_RULES })

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    await createPolicy({
      variables: {
        input: {
          name: form.name,
          description: form.description || null,
          priority: Number(form.priority),
          action: form.action,
          matchRules: form.matchRules,
        },
      },
    })
    setForm({ ...form, name: '', description: '' })
    refetch()
  }

  return (
    <div>
      <PageHeader title="Policies" />
      <ErrorBanner error={error ?? created.error ?? toggled.error ?? deleted.error} />
      <Card title="New policy" className="mb-6">
        <form onSubmit={submit} className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <Field label="Name">
            <input className={inputClass} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
          </Field>
          <Field label="Description">
            <input className={inputClass} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
          </Field>
          <Field label="Priority (lower runs first)">
            <input className={inputClass} type="number" min={0} value={form.priority} onChange={(e) => setForm({ ...form, priority: Number(e.target.value) })} />
          </Field>
          <Field label="Action">
            <select className={inputClass} value={form.action} onChange={(e) => setForm({ ...form, action: e.target.value })}>
              {ACTIONS.map((a) => (
                <option key={a}>{a}</option>
              ))}
            </select>
          </Field>
          <div className="md:col-span-2">
            <Field label="Match rules (JSON: src_ip, dst_ip, src_port, dst_port_range, protocol, ...)">
              <textarea className={`${inputClass} font-mono text-xs`} rows={2} value={form.matchRules} onChange={(e) => setForm({ ...form, matchRules: e.target.value })} />
            </Field>
          </div>
          <div>
            <Button type="submit" disabled={created.loading}>Create policy</Button>
          </div>
        </form>
      </Card>
      {loading && !data && <p className="text-gray-500">Loading…</p>}
      {data && data.policies.length === 0 && <Empty>No policies yet.</Empty>}
      {data && data.policies.length > 0 && (
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200 text-sm">
            <thead className="bg-gray-50 text-left text-gray-500">
              <tr>
                <th className="px-4 py-2">Priority</th>
                <th className="px-4 py-2">Name</th>
                <th className="px-4 py-2">Action</th>
                <th className="px-4 py-2">Match</th>
                <th className="px-4 py-2">Matched</th>
                <th className="px-4 py-2">Created</th>
                <th className="px-4 py-2" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {[...data.policies]
                .sort((a, b) => a.priority - b.priority)
                .map((p) => (
                  <tr key={p.id} className={p.enabled ? '' : 'opacity-60'}>
                    <td className="px-4 py-2">{p.priority}</td>
                    <td className="px-4 py-2 font-medium text-gray-900">
                      {p.name}
                      {p.description && <div className="text-xs text-gray-500">{p.description}</div>}
                    </td>
                    <td className="px-4 py-2">{p.action}</td>
                    <td className="px-4 py-2 font-mono text-xs break-all">{p.matchRules}</td>
                    <td className="px-4 py-2">{p.packetsMatched} pkts / {p.bytesMatched} B</td>
                    <td className="px-4 py-2 text-gray-500">{fmtDate(p.createdAt)}</td>
                    <td className="px-4 py-2 text-right space-x-2 whitespace-nowrap">
                      <Button variant="secondary" onClick={() => togglePolicy({ variables: { id: p.id, enabled: !p.enabled } }).then(() => refetch())}>
                        {p.enabled ? 'Disable' : 'Enable'}
                      </Button>
                      <Button
                        variant="danger"
                        onClick={() => {
                          if (confirm(`Delete policy ${p.name}?`)) deletePolicy({ variables: { id: p.id } }).then(() => refetch())
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
