import { FormEvent, useState } from 'react'
import { useMutation, useQuery } from '@apollo/client'
import { changePassword, currentUser } from '../api'
import { CREATE_USER, USERS } from '../graphql/operations'
import { Button, Card, ErrorBanner, Field, PageHeader, fmtDate, inputClass } from './ui'

interface User {
  id: string
  email: string
  role: string
  active: boolean
  createdAt: string
  lastLogin: string | null
}

function PasswordForm() {
  const [oldPassword, setOld] = useState('')
  const [newPassword, setNew] = useState('')
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setMessage(null)
    setError(null)
    try {
      await changePassword(oldPassword, newPassword)
      setMessage('Password changed.')
      setOld('')
      setNew('')
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  return (
    <Card title="Change password">
      <ErrorBanner error={error} />
      {message && <p className="mb-4 text-sm text-green-700">{message}</p>}
      <form onSubmit={submit} className="space-y-4">
        <Field label="Current password">
          <input className={inputClass} type="password" autoComplete="current-password" value={oldPassword} onChange={(e) => setOld(e.target.value)} required />
        </Field>
        <Field label="New password">
          <input className={inputClass} type="password" autoComplete="new-password" value={newPassword} onChange={(e) => setNew(e.target.value)} required />
        </Field>
        <Button type="submit">Change password</Button>
      </form>
    </Card>
  )
}

function UsersAdmin() {
  const { data, error, refetch } = useQuery<{ users: User[] }>(USERS)
  const [createUser, created] = useMutation(CREATE_USER)
  const [form, setForm] = useState({ email: '', password: '', role: 'VIEWER' })

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    await createUser({ variables: { input: form } })
    setForm({ email: '', password: '', role: 'VIEWER' })
    refetch()
  }

  return (
    <Card title="Users">
      <ErrorBanner error={error ?? created.error} />
      <form onSubmit={submit} className="grid grid-cols-1 gap-3 md:grid-cols-4 items-end mb-4">
        <Field label="Email">
          <input className={inputClass} type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} required />
        </Field>
        <Field label="Password">
          <input className={inputClass} type="password" autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required />
        </Field>
        <Field label="Role">
          <select className={inputClass} value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
            <option>VIEWER</option>
            <option>OPERATOR</option>
            <option>ADMIN</option>
          </select>
        </Field>
        <Button type="submit" disabled={created.loading}>Add user</Button>
      </form>
      <table className="min-w-full divide-y divide-gray-200 text-sm">
        <thead className="text-left text-gray-500">
          <tr>
            <th className="py-2">Email</th>
            <th className="py-2">Role</th>
            <th className="py-2">Active</th>
            <th className="py-2">Last login</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100">
          {data?.users.map((u) => (
            <tr key={u.id}>
              <td className="py-2">{u.email}</td>
              <td className="py-2">{u.role}</td>
              <td className="py-2">{u.active ? 'yes' : 'no'}</td>
              <td className="py-2 text-gray-500">{fmtDate(u.lastLogin)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  )
}

export default function Account() {
  const user = currentUser()
  const isAdmin = user?.role?.toLowerCase() === 'admin'
  return (
    <div>
      <PageHeader title="Account" />
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card title="Signed in as">
          <p className="text-sm">{user?.email}</p>
          <p className="text-xs text-gray-500">{user?.role}</p>
        </Card>
        <PasswordForm />
        {isAdmin && (
          <div className="lg:col-span-2">
            <UsersAdmin />
          </div>
        )}
      </div>
    </div>
  )
}
