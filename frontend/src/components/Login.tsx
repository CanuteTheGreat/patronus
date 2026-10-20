import { FormEvent, useEffect, useState } from 'react'
import { createFirstAdmin, login, setupStatus } from '../api'
import { Button, ErrorBanner, Field, inputClass } from './ui'

/** Sign-in screen; on a fresh install it offers to create the first admin. */
export default function Login() {
  const [initialized, setInitialized] = useState<boolean | null>(null)
  const [email, setEmail] = useState('')
  const [name, setName] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    setupStatus()
      .then((s) => setInitialized(s.initialized))
      .catch((e) => {
        setInitialized(true)
        setError(`Can't reach the dashboard API: ${e.message}`)
      })
  }, [])

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      if (initialized === false) await createFirstAdmin(email, name || email, password)
      await login(email, password)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const firstRun = initialized === false
  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center">
      <form onSubmit={submit} className="w-full max-w-sm bg-white rounded-lg shadow p-8 space-y-4">
        <h1 className="text-2xl font-bold text-primary-600 text-center">Patronus</h1>
        <p className="text-sm text-gray-600 text-center">
          {firstRun ? 'No users exist yet. Create the first administrator.' : 'Sign in to the SD-WAN dashboard.'}
        </p>
        <ErrorBanner error={error} />
        <Field label="Email">
          <input className={inputClass} type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </Field>
        {firstRun && (
          <Field label="Name">
            <input className={inputClass} value={name} onChange={(e) => setName(e.target.value)} />
          </Field>
        )}
        <Field label="Password">
          <input
            className={inputClass}
            type="password"
            autoComplete={firstRun ? 'new-password' : 'current-password'}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </Field>
        {firstRun && <p className="text-xs text-gray-500">At least 12 characters with upper/lower case, a digit and a symbol.</p>}
        <Button type="submit" disabled={busy || initialized === null}>
          {firstRun ? 'Create admin and sign in' : 'Sign in'}
        </Button>
      </form>
    </div>
  )
}
