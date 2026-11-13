import { useEffect, useState } from 'react'
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
  LogOut,
  Menu,
  X
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
  const [menuOpen, setMenuOpen] = useState(false)

  // The phone menu closes on navigation and on Escape.
  useEffect(() => { setMenuOpen(false) }, [location.pathname])
  useEffect(() => {
    if (!menuOpen) return
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setMenuOpen(false) }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [menuOpen])

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
        {/* Phone/tablet navigation: a menu button opens a drawer with every item (no sideways scrolling) */}
        <div className="flex items-center gap-2 border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 px-2 py-2 md:hidden">
          <button
            type="button"
            data-nav-toggle
            aria-label={menuOpen ? 'Close menu' : 'Open menu'}
            aria-expanded={menuOpen}
            aria-controls="phone-nav"
            onClick={() => setMenuOpen((o) => !o)}
            className="inline-flex h-11 w-11 items-center justify-center rounded-lg text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
          >
            {menuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
          </button>
          <span className="text-lg font-bold text-primary-700 dark:text-primary-400">Patronus</span>
        </div>
        {menuOpen && (
          <>
            <div className="fixed inset-0 z-40 bg-black/50 md:hidden" aria-hidden="true" onClick={() => setMenuOpen(false)} />
            <nav
              id="phone-nav"
              aria-label="Primary"
              className="fixed inset-y-0 left-0 z-50 w-64 max-w-[80vw] overflow-y-auto bg-white dark:bg-gray-800 px-3 py-4 shadow-xl md:hidden"
            >
              <div className="mb-4 px-3 text-xl font-bold text-primary-700 dark:text-primary-400">Patronus</div>
              {navigation.map((item) => {
                const isActive = location.pathname === item.href
                return (
                  <Link
                    key={item.name}
                    to={item.href}
                    aria-current={isActive ? 'page' : undefined}
                    className={clsx(
                      'flex items-center gap-3 rounded-lg px-3 py-3 mb-1 text-sm font-medium',
                      isActive
                        ? 'bg-primary-50 dark:bg-primary-900/40 text-primary-700 dark:text-primary-400'
                        : 'text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700'
                    )}
                  >
                    <item.icon className="h-5 w-5" />
                    {item.name}
                  </Link>
                )
              })}
            </nav>
          </>
        )}
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
