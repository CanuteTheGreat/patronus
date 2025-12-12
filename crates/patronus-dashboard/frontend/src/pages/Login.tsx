import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'
import toast from 'react-hot-toast'

export default function Login() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const navigate = useNavigate()
  const { login } = useAuth()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)

    const result = await login(email, password)

    if (result.success) {
      toast.success('Login successful')
      navigate('/')
    } else {
      const errorMessage = result.error || 'Login failed. Please check your credentials.'
      setError(errorMessage)
      toast.error(errorMessage)
    }

    setLoading(false)
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100 dark:bg-gray-900">
      <div className="max-w-md w-full space-y-8 p-8 bg-white dark:bg-gray-800 rounded-lg shadow-lg">
        <div>
          <h1 className="text-3xl font-bold text-center text-blue-600">
            Patronus
          </h1>
          <h2 className="mt-6 text-center text-2xl font-bold text-gray-900 dark:text-gray-100">
            Sign in to your account
          </h2>
        </div>

        {error && (
          <div
            role="alert"
            aria-live="assertive"
            className="p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg"
          >
            <p className="text-sm text-red-700 dark:text-red-300">{error}</p>
          </div>
        )}

        <form
          className="mt-8 space-y-6"
          onSubmit={handleSubmit}
          aria-label="Login form"
        >
          <div className="space-y-4">
            <div>
              <label htmlFor="email" className="label">
                Email address
              </label>
              <input
                id="email"
                name="email"
                type="email"
                autoComplete="email"
                required
                className="input"
                placeholder="admin@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                aria-describedby={error ? 'login-error' : undefined}
                disabled={loading}
              />
            </div>
            <div>
              <label htmlFor="password" className="label">
                Password
              </label>
              <input
                id="password"
                name="password"
                type="password"
                autoComplete="current-password"
                required
                className="input"
                placeholder="Enter your password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={loading}
              />
            </div>
          </div>

          <div>
            <button
              type="submit"
              disabled={loading}
              className="w-full btn btn-primary focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 dark:focus:ring-offset-gray-800"
              aria-busy={loading}
            >
              {loading ? (
                <>
                  <span className="sr-only">Signing in...</span>
                  <span aria-hidden="true">Signing in...</span>
                </>
              ) : (
                'Sign in'
              )}
            </button>
          </div>
        </form>

        <p className="text-center text-sm text-gray-500 dark:text-gray-400">
          <span className="sr-only">Demo credentials: </span>
          Use <code className="font-mono text-xs bg-gray-100 dark:bg-gray-700 px-1 py-0.5 rounded">admin@patronus.local</code> / <code className="font-mono text-xs bg-gray-100 dark:bg-gray-700 px-1 py-0.5 rounded">admin123</code> for demo
        </p>
      </div>
    </div>
  )
}
