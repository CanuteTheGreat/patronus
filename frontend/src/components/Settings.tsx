import { Settings as SettingsIcon, Bell, Shield, Network } from 'lucide-react'

export default function Settings() {
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-gray-900">Settings</h1>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* General Settings */}
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-primary-50 rounded-lg">
              <SettingsIcon className="h-6 w-6 text-primary-600" />
            </div>
            <h2 className="text-lg font-semibold text-gray-900">General</h2>
          </div>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Organization Name
              </label>
              <input
                type="text"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500"
                placeholder="Enter organization name"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Timezone
              </label>
              <select className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500">
                <option>UTC</option>
                <option>America/New_York</option>
                <option>America/Los_Angeles</option>
                <option>Europe/London</option>
              </select>
            </div>
          </div>
        </div>

        {/* Notifications */}
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-yellow-50 rounded-lg">
              <Bell className="h-6 w-6 text-yellow-600" />
            </div>
            <h2 className="text-lg font-semibold text-gray-900">Notifications</h2>
          </div>
          <div className="space-y-4">
            <label className="flex items-center justify-between">
              <span className="text-sm font-medium text-gray-700">
                Email Alerts
              </span>
              <input type="checkbox" className="h-4 w-4 text-primary-600 rounded" />
            </label>
            <label className="flex items-center justify-between">
              <span className="text-sm font-medium text-gray-700">
                Critical Events
              </span>
              <input type="checkbox" className="h-4 w-4 text-primary-600 rounded" defaultChecked />
            </label>
            <label className="flex items-center justify-between">
              <span className="text-sm font-medium text-gray-700">
                Performance Alerts
              </span>
              <input type="checkbox" className="h-4 w-4 text-primary-600 rounded" defaultChecked />
            </label>
            <label className="flex items-center justify-between">
              <span className="text-sm font-medium text-gray-700">
                Security Alerts
              </span>
              <input type="checkbox" className="h-4 w-4 text-primary-600 rounded" defaultChecked />
            </label>
          </div>
        </div>

        {/* Security */}
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-red-50 rounded-lg">
              <Shield className="h-6 w-6 text-red-600" />
            </div>
            <h2 className="text-lg font-semibold text-gray-900">Security</h2>
          </div>
          <div className="space-y-4">
            <label className="flex items-center justify-between">
              <span className="text-sm font-medium text-gray-700">
                Two-Factor Authentication
              </span>
              <input type="checkbox" className="h-4 w-4 text-primary-600 rounded" />
            </label>
            <label className="flex items-center justify-between">
              <span className="text-sm font-medium text-gray-700">
                API Access
              </span>
              <input type="checkbox" className="h-4 w-4 text-primary-600 rounded" defaultChecked />
            </label>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Session Timeout (minutes)
              </label>
              <input
                type="number"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500"
                defaultValue={30}
                min={5}
                max={120}
              />
            </div>
          </div>
        </div>

        {/* Network */}
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-green-50 rounded-lg">
              <Network className="h-6 w-6 text-green-600" />
            </div>
            <h2 className="text-lg font-semibold text-gray-900">Network</h2>
          </div>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Health Check Interval (seconds)
              </label>
              <input
                type="number"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500"
                defaultValue={5}
                min={1}
                max={60}
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Failover Threshold
              </label>
              <input
                type="number"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500"
                defaultValue={3}
                min={1}
                max={10}
              />
            </div>
            <label className="flex items-center justify-between">
              <span className="text-sm font-medium text-gray-700">
                Auto Failover
              </span>
              <input type="checkbox" className="h-4 w-4 text-primary-600 rounded" defaultChecked />
            </label>
          </div>
        </div>
      </div>

      <div className="flex justify-end gap-3">
        <button className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors">
          Cancel
        </button>
        <button className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors">
          Save Changes
        </button>
      </div>
    </div>
  )
}
