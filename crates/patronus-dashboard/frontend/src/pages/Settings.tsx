import { useState } from 'react'
import { useAuth } from '../hooks/useAuth'
import toast from 'react-hot-toast'

export default function Settings() {
  const { user } = useAuth()
  const [activeTab, setActiveTab] = useState<'profile' | 'security' | 'notifications'>('profile')

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100">
          Settings
        </h1>
        <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
          Manage your account and application preferences
        </p>
      </div>

      <div className="card">
        <div className="border-b border-gray-200 dark:border-gray-700">
          <nav className="-mb-px flex space-x-8">
            <button
              onClick={() => setActiveTab('profile')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'profile'
                  ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                  : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300'
              }`}
            >
              Profile
            </button>
            <button
              onClick={() => setActiveTab('security')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'security'
                  ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                  : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300'
              }`}
            >
              Security
            </button>
            <button
              onClick={() => setActiveTab('notifications')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'notifications'
                  ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                  : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300'
              }`}
            >
              Notifications
            </button>
          </nav>
        </div>

        <div className="mt-6">
          {activeTab === 'profile' && <ProfileTab user={user} />}
          {activeTab === 'security' && <SecurityTab />}
          {activeTab === 'notifications' && <NotificationsTab />}
        </div>
      </div>
    </div>
  )
}

function ProfileTab({ user }: { user: any }) {
  const [email, setEmail] = useState(user?.email || '')
  const [saving, setSaving] = useState(false)

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)

    // TODO: Implement profile update
    await new Promise((resolve) => setTimeout(resolve, 1000))

    toast.success('Profile updated successfully')
    setSaving(false)
  }

  return (
    <form onSubmit={handleSave} className="space-y-6">
      <div>
        <label htmlFor="email" className="label">
          Email Address
        </label>
        <input
          id="email"
          type="email"
          className="input"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
      </div>

      <div>
        <label className="label">Role</label>
        <div className="px-4 py-2 bg-gray-100 dark:bg-gray-700 rounded-lg text-gray-900 dark:text-gray-100">
          {user?.role}
        </div>
      </div>

      <div>
        <button type="submit" disabled={saving} className="btn btn-primary">
          {saving ? 'Saving...' : 'Save Changes'}
        </button>
      </div>
    </form>
  )
}

function SecurityTab() {
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [saving, setSaving] = useState(false)

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault()

    if (newPassword !== confirmPassword) {
      toast.error('New passwords do not match')
      return
    }

    setSaving(true)

    // TODO: Implement password change
    await new Promise((resolve) => setTimeout(resolve, 1000))

    toast.success('Password changed successfully')
    setCurrentPassword('')
    setNewPassword('')
    setConfirmPassword('')
    setSaving(false)
  }

  return (
    <form onSubmit={handleSave} className="space-y-6">
      <div>
        <label htmlFor="current-password" className="label">
          Current Password
        </label>
        <input
          id="current-password"
          type="password"
          className="input"
          value={currentPassword}
          onChange={(e) => setCurrentPassword(e.target.value)}
          required
        />
      </div>

      <div>
        <label htmlFor="new-password" className="label">
          New Password
        </label>
        <input
          id="new-password"
          type="password"
          className="input"
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
          required
        />
      </div>

      <div>
        <label htmlFor="confirm-password" className="label">
          Confirm New Password
        </label>
        <input
          id="confirm-password"
          type="password"
          className="input"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          required
        />
      </div>

      <div>
        <button type="submit" disabled={saving} className="btn btn-primary">
          {saving ? 'Changing...' : 'Change Password'}
        </button>
      </div>
    </form>
  )
}

function NotificationsTab() {
  const [emailNotifications, setEmailNotifications] = useState(true)
  const [siteAlerts, setSiteAlerts] = useState(true)
  const [policyAlerts, setPolicyAlerts] = useState(true)
  const [saving, setSaving] = useState(false)

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)

    // TODO: Implement notification settings update
    await new Promise((resolve) => setTimeout(resolve, 1000))

    toast.success('Notification settings updated')
    setSaving(false)
  }

  return (
    <form onSubmit={handleSave} className="space-y-6">
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <label className="font-medium text-gray-900 dark:text-gray-100">
              Email Notifications
            </label>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Receive email notifications for important events
            </p>
          </div>
          <input
            type="checkbox"
            className="w-4 h-4 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500"
            checked={emailNotifications}
            onChange={(e) => setEmailNotifications(e.target.checked)}
          />
        </div>

        <div className="flex items-center justify-between">
          <div>
            <label className="font-medium text-gray-900 dark:text-gray-100">
              Site Status Alerts
            </label>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Get notified when sites go down or become degraded
            </p>
          </div>
          <input
            type="checkbox"
            className="w-4 h-4 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500"
            checked={siteAlerts}
            onChange={(e) => setSiteAlerts(e.target.checked)}
          />
        </div>

        <div className="flex items-center justify-between">
          <div>
            <label className="font-medium text-gray-900 dark:text-gray-100">
              Policy Alerts
            </label>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Get notified when policies are created or modified
            </p>
          </div>
          <input
            type="checkbox"
            className="w-4 h-4 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500"
            checked={policyAlerts}
            onChange={(e) => setPolicyAlerts(e.target.checked)}
          />
        </div>
      </div>

      <div>
        <button type="submit" disabled={saving} className="btn btn-primary">
          {saving ? 'Saving...' : 'Save Changes'}
        </button>
      </div>
    </form>
  )
}
