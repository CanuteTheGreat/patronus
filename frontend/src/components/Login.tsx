import { useState, FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield } from 'lucide-react'
import { login } from '../auth'

export default function Login() {
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await login(email, password)
      navigate('/dashboard', { replace: true })
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
      <form onSubmit={onSubmit} className="w-full max-w-sm rounded-lg bg-white dark:bg-gray-800 p-8 shadow" aria-label="Sign in">
        <div className="mb-6 flex items-center gap-2">
          <Shield className="h-6 w-6 text-primary-700 dark:text-primary-400" />
          <h1 className="text-xl font-bold">Patronus Dashboard</h1>
        </div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300" htmlFor="email">Email</label>
        <input id="email" type="email" autoComplete="username" required value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="mb-4 mt-1 w-full rounded border border-gray-300 dark:border-gray-600 px-3 py-2" />
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300" htmlFor="password">Password</label>
        <input id="password" type="password" autoComplete="current-password" required value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="mb-4 mt-1 w-full rounded border border-gray-300 dark:border-gray-600 px-3 py-2" />
        {error && <p role="alert" className="mb-4 text-sm text-red-700 dark:text-red-400">{error}</p>}
        <button type="submit" disabled={busy}
          className="w-full rounded bg-primary-700 px-4 py-2 font-medium text-white hover:bg-primary-800 disabled:opacity-50">
          {busy ? 'Signing in...' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}
