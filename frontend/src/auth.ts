// Session handling for the dashboard UI. The backend issues a short-lived
// JWT access token (POST /api/v1/auth/login); every GraphQL/REST call sends
// it as a Bearer token. Before this, the UI never logged in at all, so every
// GraphQL query (all of which require authentication) failed.

const TOKEN_KEY = 'patronus.accessToken'
const REFRESH_KEY = 'patronus.refreshToken'
const USER_KEY = 'patronus.user'

export interface SessionUser {
  id: string
  email: string
  name: string
  role: string
}

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function getUser(): SessionUser | null {
  const raw = localStorage.getItem(USER_KEY)
  return raw ? (JSON.parse(raw) as SessionUser) : null
}

export function isLoggedIn(): boolean {
  return getToken() !== null
}

export async function login(email: string, password: string): Promise<SessionUser> {
  const res = await fetch('/api/v1/auth/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
  const body = await res.json().catch(() => ({}))
  if (!res.ok) {
    throw new Error(body.error || `Login failed (${res.status})`)
  }
  localStorage.setItem(TOKEN_KEY, body.access_token)
  localStorage.setItem(REFRESH_KEY, body.refresh_token)
  localStorage.setItem(USER_KEY, JSON.stringify(body.user))
  return body.user as SessionUser
}

export function logout(): void {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(REFRESH_KEY)
  localStorage.removeItem(USER_KEY)
}

/** Exchange the refresh token for a new access token; false if that fails. */
export async function refresh(): Promise<boolean> {
  const refreshToken = localStorage.getItem(REFRESH_KEY)
  if (!refreshToken) return false
  const res = await fetch('/api/v1/auth/refresh', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ refresh_token: refreshToken }),
  })
  if (!res.ok) return false
  const body = await res.json()
  localStorage.setItem(TOKEN_KEY, body.access_token)
  localStorage.setItem(REFRESH_KEY, body.refresh_token)
  return true
}
