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
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Sidebar */}
      <div className="fixed inset-y-0 left-0 hidden w-64 bg-white dark:bg-gray-800 shadow-lg md:block">
        <div className="flex h-16 items-center justify-center border-b border-gray-200 dark:border-gray-700">
          <h1 className="text-2xl font-bold text-primary-700 dark:text-primary-400">Patronus</h1>
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
                    ? 'bg-primary-50 dark:bg-primary-900/40 text-primary-700 dark:text-primary-400'
                    : 'text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 hover:text-gray-900 dark:hover:text-white'
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
      <div className="md:pl-64">
        {/* Phone/tablet navigation: the sidebar is desktop-only */}
        <nav aria-label="Primary" className="flex gap-1 overflow-x-auto border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 px-2 py-2 md:hidden">
          <span className="flex shrink-0 items-center px-2 text-lg font-bold text-primary-700 dark:text-primary-400">Patronus</span>
          {navigation.map((item) => {
            const isActive = location.pathname === item.href
            return (
              <Link
                key={item.name}
                to={item.href}
                aria-current={isActive ? 'page' : undefined}
                className={clsx(
                  'flex shrink-0 items-center gap-1 rounded-lg px-3 py-2 text-sm font-medium',
                  isActive
                    ? 'bg-primary-50 dark:bg-primary-900/40 text-primary-700 dark:text-primary-400'
                    : 'text-gray-700 dark:text-gray-300'
                )}
              >
                <item.icon className="h-4 w-4" />
                {item.name}
              </Link>
            )
          })}
        </nav>
        <header className="flex min-h-12 flex-wrap items-center justify-end gap-x-4 gap-y-1 px-4 py-1 md:px-8 border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-sm">
          <LeaderBadge />
          {user && <span className="text-sm text-gray-600 dark:text-gray-300">{user.email} ({user.role})</span>}
          <button
            type="button"
            onClick={() => { logout(); navigate('/login', { replace: true }) }}
            className="inline-flex items-center gap-1 text-sm text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white"
          >
            <LogOut className="h-4 w-4" /> Sign out
          </button>
        </header>
        <main className="p-4 md:p-8">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
