import { Outlet, Link, useLocation, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard,
  MapPin,
  Network,
  Target,
  BarChart3,
  Shield,
  Settings,
  Server,
  LogOut
} from 'lucide-react'
import clsx from 'clsx'
import { LeaderBadge } from './Cluster'
import { getUser, logout } from '../auth'

const navigation = [
  { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Sites', href: '/sites', icon: MapPin },
  { name: 'Topology', href: '/topology', icon: Network },
  { name: 'SLA', href: '/sla', icon: Target },
  { name: 'Traffic', href: '/traffic', icon: BarChart3 },
  { name: 'Security', href: '/security', icon: Shield },
  { name: 'Cluster', href: '/cluster', icon: Server },
  { name: 'Settings', href: '/settings', icon: Settings },
]

export default function Layout() {
  const location = useLocation()
  const navigate = useNavigate()
  const user = getUser()

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Sidebar */}
      <div className="fixed inset-y-0 left-0 w-64 bg-white shadow-lg">
        <div className="flex h-16 items-center justify-center border-b border-gray-200">
          <h1 className="text-2xl font-bold text-primary-600">Patronus</h1>
        </div>
        <nav className="mt-6 px-3">
          {navigation.map((item) => {
            const isActive = location.pathname === item.href
            return (
              <Link
                key={item.name}
                to={item.href}
                className={clsx(
                  'flex items-center gap-3 rounded-lg px-3 py-2 mb-1 text-sm font-medium transition-colors',
                  isActive
                    ? 'bg-primary-50 text-primary-600'
                    : 'text-gray-700 hover:bg-gray-50 hover:text-gray-900'
                )}
              >
                <item.icon className="h-5 w-5" />
                {item.name}
              </Link>
            )
          })}
        </nav>
      </div>

      {/* Main content */}
      <div className="pl-64">
        <header className="flex h-12 items-center justify-end gap-4 border-b border-gray-200 bg-white px-8">
          <LeaderBadge />
          {user && <span className="text-sm text-gray-600">{user.email} ({user.role})</span>}
          <button
            type="button"
            onClick={() => { logout(); navigate('/login', { replace: true }) }}
            className="inline-flex items-center gap-1 text-sm text-gray-600 hover:text-gray-900"
          >
            <LogOut className="h-4 w-4" /> Sign out
          </button>
        </header>
        <main className="p-8">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
