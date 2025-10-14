import { Link, useLocation } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'
import {
  HomeIcon,
  BuildingOfficeIcon,
  DocumentTextIcon,
  ChartBarIcon,
  UsersIcon,
  Cog6ToothIcon,
  ArrowRightOnRectangleIcon,
} from '@heroicons/react/24/outline'

interface LayoutProps {
  children: React.ReactNode
}

export default function Layout({ children }: LayoutProps) {
  const location = useLocation()
  const { user, logout } = useAuth()

  const navigation = [
    { name: 'Dashboard', href: '/', icon: HomeIcon },
    { name: 'Sites', href: '/sites', icon: BuildingOfficeIcon },
    { name: 'Policies', href: '/policies', icon: DocumentTextIcon },
    { name: 'Metrics', href: '/metrics', icon: ChartBarIcon },
    { name: 'Users', href: '/users', icon: UsersIcon },
    { name: 'Settings', href: '/settings', icon: Cog6ToothIcon },
  ]

  return (
    <div className="min-h-screen bg-gray-100 dark:bg-gray-900">
      {/* Sidebar */}
      <div className="fixed inset-y-0 left-0 w-64 bg-white dark:bg-gray-800 shadow-lg">
        <div className="flex flex-col h-full">
          {/* Logo */}
          <div className="flex items-center justify-center h-16 bg-blue-600">
            <h1 className="text-2xl font-bold text-white">Patronus</h1>
          </div>

          {/* Navigation */}
          <nav className="flex-1 px-4 py-6 space-y-2">
            {navigation.map((item) => {
              const isActive = location.pathname === item.href
              return (
                <Link
                  key={item.name}
                  to={item.href}
                  className={`flex items-center px-4 py-3 text-sm font-medium rounded-lg transition-colors ${
                    isActive
                      ? 'bg-blue-50 dark:bg-blue-900 text-blue-600 dark:text-blue-200'
                      : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
                  }`}
                >
                  <item.icon className="w-5 h-5 mr-3" />
                  {item.name}
                </Link>
              )
            })}
          </nav>

          {/* User info */}
          <div className="p-4 border-t border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between">
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate">
                  {user?.email}
                </p>
                <p className="text-xs text-gray-500 dark:text-gray-400">
                  {user?.role}
                </p>
              </div>
              <button
                onClick={logout}
                className="ml-3 p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors"
                title="Logout"
              >
                <ArrowRightOnRectangleIcon className="w-5 h-5" />
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Main content */}
      <div className="pl-64">
        <main className="p-8">{children}</main>
      </div>
    </div>
  )
}
