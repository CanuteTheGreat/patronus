// Session + REST helpers for the Patronus dashboard.
//
// The dashboard API issues a short-lived access token and a refresh token
// (POST /api/v1/auth/login). Both are kept in sessionStorage; every REST and
// GraphQL call sends the access token, and a 401 triggers one refresh
// attempt before the user is sent back to the login screen.

const ACCESS_KEY = 'patronus.access_token'
const REFRESH_KEY = 'patronus.refresh_token'
const USER_KEY = 'patronus.user'

export interface SessionUser {
  id: string
  email: string
  name: string
  role: string
}

type Listener = () => void
const listeners = new Set<Listener>()

export function onSessionChange(fn: Listener): () => void {
  listeners.add(fn)
  return () => listeners.delete(fn)
}

function notify() {
  listeners.forEach((fn) => fn())
}

export function accessToken(): string | null {
  return sessionStorage.getItem(ACCESS_KEY)
}

export function currentUser(): SessionUser | null {
  const raw = sessionStorage.getItem(USER_KEY)
  return raw ? (JSON.parse(raw) as SessionUser) : null
}

function storeSession(access: string, refresh: string, user?: SessionUser) {
  sessionStorage.setItem(ACCESS_KEY, access)
  sessionStorage.setItem(REFRESH_KEY, refresh)
  if (user && user.id) sessionStorage.setItem(USER_KEY, JSON.stringify(user))
  notify()
}

export function logout() {
  sessionStorage.removeItem(ACCESS_KEY)
  sessionStorage.removeItem(REFRESH_KEY)
  sessionStorage.removeItem(USER_KEY)
  notify()
}

/** Error carrying the HTTP status and the API's `error` message. */
export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
  }
}

async function parseError(res: Response): Promise<ApiError> {
  let message = `${res.status} ${res.statusText}`
  try {
    const body = await res.json()
    if (body && typeof body.error === 'string') message = body.error
  } catch {
    /* non-JSON error body */
  }
  return new ApiError(res.status, message)
}

let refreshing: Promise<boolean> | null = null

/** Try to swap the refresh token for a new access token. */
export function refreshSession(): Promise<boolean> {
  if (refreshing) return refreshing
  const refresh = sessionStorage.getItem(REFRESH_KEY)
  if (!refresh) return Promise.resolve(false)
  refreshing = (async () => {
    try {
      const res = await fetch('/api/v1/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refresh }),
      })
      if (!res.ok) return false
      const body = await res.json()
      storeSession(body.access_token, body.refresh_token)
      return true
    } catch {
      return false
    } finally {
      refreshing = null
    }
  })()
  return refreshing
}

/** JSON request against the dashboard API with auth + one refresh retry. */
export async function api<T>(path: string, init: RequestInit = {}, retry = true): Promise<T> {
  const headers = new Headers(init.headers)
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  const token = accessToken()
  if (token) headers.set('Authorization', `Bearer ${token}`)
  const res = await fetch(path, { ...init, headers })
  if (res.status === 401 && retry && token) {
    if (await refreshSession()) return api<T>(path, init, false)
    logout()
  }
  if (!res.ok) throw await parseError(res)
  const text = await res.text()
  return (text ? JSON.parse(text) : undefined) as T
}

interface LoginResponse {
  user: SessionUser
  access_token: string
  refresh_token: string
}

export async function login(email: string, password: string): Promise<void> {
  const body = await api<LoginResponse>(
    '/api/v1/auth/login',
    { method: 'POST', body: JSON.stringify({ email, password }) },
    false,
  )
  storeSession(body.access_token, body.refresh_token, body.user)
}

export async function setupStatus(): Promise<{ initialized: boolean }> {
  return api('/api/v1/auth/status', {}, false)
}

export async function createFirstAdmin(email: string, name: string, password: string): Promise<void> {
  await api(
    '/api/v1/auth/init-admin',
    { method: 'POST', body: JSON.stringify({ email, name, password, role: 'admin' }) },
    false,
  )
}

export async function changePassword(oldPassword: string, newPassword: string): Promise<void> {
  await api('/api/v1/auth/change-password', {
    method: 'POST',
    body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }),
  })
}

// ---- HA cluster view (/ha/cluster) ----

export interface HaStatus {
  node_id: string
  role: 'Leader' | 'Follower' | 'Candidate'
  term: number
  leader_id: string | null
  voted_for: string | null
  peers: string[]
  cluster_size: number
  advertise_addr: string
  leader_addr: string | null
  generation: number
}

export interface ClusterNode {
  address: string
  reachable: boolean
  status: HaStatus | null
  error: string | null
}

export interface ClusterView {
  enabled: boolean
  answered_by: string | null
  leader_id: string | null
  term: number
  nodes: ClusterNode[]
}

export async function clusterView(): Promise<ClusterView> {
  const res = await fetch('/ha/cluster')
  if (!res.ok) throw await parseError(res)
  return res.json()
}
