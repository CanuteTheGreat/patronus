import { useEffect, useState } from 'react'
import { Outlet, Link, useLocation } from 'react-router-dom'
import { LayoutDashboard, MapPin, Route as RouteIcon, ListChecks, BarChart3, Shield, Server, User, LogOut } from 'lucide-react'
import clsx from 'clsx'
import { client } from '../graphql/client'
import { clusterView, currentUser, logout, ClusterView } from '../api'

const navigation = [
  { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Sites', href: '/sites', icon: MapPin },
  { name: 'Paths', href: '/paths', icon: RouteIcon },
  { name: 'Policies', href: '/policies', icon: ListChecks },
  { name: 'Traffic', href: '/traffic', icon: BarChart3 },
  { name: 'Security', href: '/security', icon: Shield },
  { name: 'Cluster', href: '/cluster', icon: Server },
  { name: 'Account', href: '/account', icon: User },
]

/** Small always-visible HA indicator: which node leads right now. */
function LeaderBadge() {
  const [view, setView] = useState<ClusterView | null>(null)
  useEffect(() => {
    let alive = true
    const tick = () => clusterView().then((v) => alive && setView(v)).catch(() => alive && setView(null))
    tick()
    const t = setInterval(tick, 5000)
    return () => {
      alive = false
      clearInterval(t)
    }
  }, [])
  if (!view || !view.enabled) return null
  return (
    <Link to="/cluster" className="block mx-3 mb-4 rounded-lg bg-gray-50 px-3 py-2 text-xs text-gray-600 hover:bg-gray-100">
      HA leader: <span className="font-semibold text-gray-900">{view.leader_id ?? 'electing…'}</span>
      <span className="ml-1">(term {view.term})</span>
    </Link>
  )
}

export default function Layout() {
  const location = useLocation()
  const user = currentUser()

  const signOut = () => {
    client.clearStore()
    logout()
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="fixed inset-y-0 left-0 w-64 bg-white shadow-lg flex flex-col">
        <div className="flex h-16 items-center justify-center border-b border-gray-200">
          <h1 className="text-2xl font-bold text-primary-600">Patronus</h1>
        </div>
        <nav className="mt-6 px-3 flex-1">
          {navigation.map((item) => {
            const isActive = location.pathname === item.href
            return (
              <Link
                key={item.name}
                to={item.href}
                className={clsx(
                  'flex items-center gap-3 rounded-lg px-3 py-2 mb-1 text-sm font-medium transition-colors',
                  isActive ? 'bg-primary-50 text-primary-600' : 'text-gray-700 hover:bg-gray-50 hover:text-gray-900',
                )}
              >
                <item.icon className="h-5 w-5" />
                {item.name}
              </Link>
            )
          })}
        </nav>
        <LeaderBadge />
        <div className="border-t border-gray-200 p-3 text-sm">
          <div className="truncate text-gray-700">{user?.email ?? 'signed in'}</div>
          {user?.role && <div className="text-xs text-gray-500">{user.role}</div>}
          <button onClick={signOut} className="mt-2 inline-flex items-center gap-2 text-gray-600 hover:text-gray-900">
            <LogOut className="h-4 w-4" /> Sign out
          </button>
        </div>
      </div>
      <div className="pl-64">
        <main className="p-8">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
