import { useState, useEffect } from 'react'
import { useQuery, useMutation } from '@apollo/client'
import { useAuth } from '../hooks/useAuth'
import { useTheme } from '../contexts/ThemeContext'
import { GET_SYSTEM_INFO, GET_API_KEYS, CREATE_API_KEY, REVOKE_API_KEY, UPDATE_USER_PROFILE, CHANGE_PASSWORD } from '../graphql/queries'
import { ApiKey, SystemInfo } from '../types'
import { Loading, LoadingSkeleton } from '../components/Loading'
import ConfirmModal from '../components/ConfirmModal'
import toast from 'react-hot-toast'
import dayjs from 'dayjs'
import relativeTime from 'dayjs/plugin/relativeTime'

dayjs.extend(relativeTime)

type TabType = 'profile' | 'security' | 'notifications' | 'apikeys' | 'system' | 'appearance'

export default function Settings() {
  const { user } = useAuth()
  const [activeTab, setActiveTab] = useState<TabType>('profile')

  const tabs: { id: TabType; label: string; icon: string; adminOnly?: boolean }[] = [
    { id: 'profile', label: 'Profile', icon: '👤' },
    { id: 'security', label: 'Security', icon: '🔒' },
    { id: 'notifications', label: 'Notifications', icon: '🔔' },
    { id: 'appearance', label: 'Appearance', icon: '🎨' },
    { id: 'apikeys', label: 'API Keys', icon: '🔑' },
    { id: 'system', label: 'System Info', icon: '⚙️', adminOnly: true },
  ]

  const visibleTabs = tabs.filter(tab => !tab.adminOnly || user?.role === 'Admin')

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
          <nav className="-mb-px flex space-x-8 overflow-x-auto" role="tablist" aria-label="Settings tabs">
            {visibleTabs.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                role="tab"
                aria-selected={activeTab === tab.id}
                aria-controls={`${tab.id}-panel`}
                className={`py-4 px-1 border-b-2 font-medium text-sm whitespace-nowrap transition-colors ${
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                    : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300'
                }`}
              >
                <span className="mr-2">{tab.icon}</span>
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        <div className="mt-6" role="tabpanel" id={`${activeTab}-panel`}>
          {activeTab === 'profile' && <ProfileTab user={user} />}
          {activeTab === 'security' && <SecurityTab />}
          {activeTab === 'notifications' && <NotificationsTab />}
          {activeTab === 'appearance' && <AppearanceTab />}
          {activeTab === 'apikeys' && <ApiKeysTab />}
          {activeTab === 'system' && <SystemInfoTab />}
        </div>
      </div>
    </div>
  )
}

function ProfileTab({ user }: { user: any }) {
  const [formData, setFormData] = useState({
    email: user?.email || '',
    username: user?.username || '',
    displayName: user?.displayName || '',
  })

  const [updateProfile, { loading: saving }] = useMutation(UPDATE_USER_PROFILE, {
    onCompleted: () => {
      toast.success('Profile updated successfully')
    },
    onError: (error) => {
      toast.error(error.message || 'Failed to update profile')
    },
  })

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault()
    await updateProfile({
      variables: {
        input: {
          email: formData.email,
          displayName: formData.displayName,
        },
      },
    })
  }

  return (
    <form onSubmit={handleSave} className="space-y-6 max-w-lg">
      <div>
        <label htmlFor="username" className="label">
          Username
        </label>
        <input
          id="username"
          type="text"
          className="input bg-gray-100 dark:bg-gray-700"
          value={formData.username}
          disabled
          aria-describedby="username-hint"
        />
        <p id="username-hint" className="mt-1 text-sm text-gray-500 dark:text-gray-400">
          Username cannot be changed
        </p>
      </div>

      <div>
        <label htmlFor="displayName" className="label">
          Display Name
        </label>
        <input
          id="displayName"
          type="text"
          className="input"
          value={formData.displayName}
          onChange={(e) => setFormData({ ...formData, displayName: e.target.value })}
          placeholder="Enter your display name"
        />
      </div>

      <div>
        <label htmlFor="email" className="label">
          Email Address
        </label>
        <input
          id="email"
          type="email"
          className="input"
          value={formData.email}
          onChange={(e) => setFormData({ ...formData, email: e.target.value })}
          required
        />
      </div>

      <div>
        <label className="label">Role</label>
        <div className="px-4 py-2 bg-gray-100 dark:bg-gray-700 rounded-lg text-gray-900 dark:text-gray-100">
          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
            user?.role === 'Admin' ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200' :
            user?.role === 'Operator' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200' :
            'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200'
          }`}>
            {user?.role}
          </span>
        </div>
      </div>

      <div>
        <label className="label">Account Created</label>
        <div className="px-4 py-2 bg-gray-100 dark:bg-gray-700 rounded-lg text-gray-900 dark:text-gray-100">
          {user?.createdAt ? dayjs(user.createdAt).format('MMMM D, YYYY') : 'N/A'}
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
  const [formData, setFormData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
  })
  const [showPasswords, setShowPasswords] = useState(false)

  const [changePassword, { loading: saving }] = useMutation(CHANGE_PASSWORD, {
    onCompleted: () => {
      toast.success('Password changed successfully')
      setFormData({ currentPassword: '', newPassword: '', confirmPassword: '' })
    },
    onError: (error) => {
      toast.error(error.message || 'Failed to change password')
    },
  })

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault()

    if (formData.newPassword.length < 8) {
      toast.error('New password must be at least 8 characters')
      return
    }

    if (formData.newPassword !== formData.confirmPassword) {
      toast.error('New passwords do not match')
      return
    }

    await changePassword({
      variables: {
        currentPassword: formData.currentPassword,
        newPassword: formData.newPassword,
      },
    })
  }

  const passwordStrength = (password: string): { label: string; color: string; width: string } => {
    if (password.length === 0) return { label: '', color: 'bg-gray-200', width: '0%' }
    if (password.length < 8) return { label: 'Weak', color: 'bg-red-500', width: '25%' }

    let strength = 0
    if (password.length >= 8) strength++
    if (password.length >= 12) strength++
    if (/[A-Z]/.test(password)) strength++
    if (/[a-z]/.test(password)) strength++
    if (/[0-9]/.test(password)) strength++
    if (/[^A-Za-z0-9]/.test(password)) strength++

    if (strength <= 2) return { label: 'Weak', color: 'bg-red-500', width: '25%' }
    if (strength <= 3) return { label: 'Fair', color: 'bg-yellow-500', width: '50%' }
    if (strength <= 4) return { label: 'Good', color: 'bg-blue-500', width: '75%' }
    return { label: 'Strong', color: 'bg-green-500', width: '100%' }
  }

  const strength = passwordStrength(formData.newPassword)

  return (
    <form onSubmit={handleSave} className="space-y-6 max-w-lg">
      <div>
        <label htmlFor="current-password" className="label">
          Current Password
        </label>
        <div className="relative">
          <input
            id="current-password"
            type={showPasswords ? 'text' : 'password'}
            className="input pr-10"
            value={formData.currentPassword}
            onChange={(e) => setFormData({ ...formData, currentPassword: e.target.value })}
            required
            autoComplete="current-password"
          />
        </div>
      </div>

      <div>
        <label htmlFor="new-password" className="label">
          New Password
        </label>
        <input
          id="new-password"
          type={showPasswords ? 'text' : 'password'}
          className="input"
          value={formData.newPassword}
          onChange={(e) => setFormData({ ...formData, newPassword: e.target.value })}
          required
          autoComplete="new-password"
          minLength={8}
        />
        {formData.newPassword && (
          <div className="mt-2">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs text-gray-500 dark:text-gray-400">Password strength</span>
              <span className={`text-xs font-medium ${
                strength.label === 'Weak' ? 'text-red-500' :
                strength.label === 'Fair' ? 'text-yellow-500' :
                strength.label === 'Good' ? 'text-blue-500' :
                'text-green-500'
              }`}>{strength.label}</span>
            </div>
            <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-1.5">
              <div
                className={`h-1.5 rounded-full transition-all ${strength.color}`}
                style={{ width: strength.width }}
              />
            </div>
          </div>
        )}
      </div>

      <div>
        <label htmlFor="confirm-password" className="label">
          Confirm New Password
        </label>
        <input
          id="confirm-password"
          type={showPasswords ? 'text' : 'password'}
          className="input"
          value={formData.confirmPassword}
          onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })}
          required
          autoComplete="new-password"
        />
        {formData.confirmPassword && formData.newPassword !== formData.confirmPassword && (
          <p className="mt-1 text-sm text-red-500">Passwords do not match</p>
        )}
      </div>

      <div className="flex items-center">
        <input
          id="show-passwords"
          type="checkbox"
          className="w-4 h-4 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500"
          checked={showPasswords}
          onChange={(e) => setShowPasswords(e.target.checked)}
        />
        <label htmlFor="show-passwords" className="ml-2 text-sm text-gray-600 dark:text-gray-400">
          Show passwords
        </label>
      </div>

      <div className="pt-4 border-t border-gray-200 dark:border-gray-700">
        <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-4">
          Two-Factor Authentication
        </h3>
        <div className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
          <div>
            <p className="font-medium text-gray-900 dark:text-gray-100">2FA Status</p>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Add an extra layer of security to your account
            </p>
          </div>
          <span className="badge badge-warning">Not Enabled</span>
        </div>
        <button type="button" className="mt-4 btn btn-secondary">
          Enable 2FA
        </button>
      </div>

      <div>
        <button
          type="submit"
          disabled={saving || formData.newPassword !== formData.confirmPassword}
          className="btn btn-primary"
        >
          {saving ? 'Changing...' : 'Change Password'}
        </button>
      </div>
    </form>
  )
}

function NotificationsTab() {
  const [settings, setSettings] = useState({
    emailNotifications: true,
    siteAlerts: true,
    policyAlerts: true,
    securityAlerts: true,
    weeklyDigest: false,
    maintenanceAlerts: true,
  })
  const [saving, setSaving] = useState(false)

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)

    // TODO: Implement notification settings update via GraphQL
    await new Promise((resolve) => setTimeout(resolve, 1000))

    toast.success('Notification settings updated')
    setSaving(false)
  }

  const toggleSetting = (key: keyof typeof settings) => {
    setSettings(prev => ({ ...prev, [key]: !prev[key] }))
  }

  const notificationOptions = [
    {
      key: 'emailNotifications' as const,
      label: 'Email Notifications',
      description: 'Receive email notifications for important events',
    },
    {
      key: 'siteAlerts' as const,
      label: 'Site Status Alerts',
      description: 'Get notified when sites go down or become degraded',
    },
    {
      key: 'policyAlerts' as const,
      label: 'Policy Alerts',
      description: 'Get notified when policies are created or modified',
    },
    {
      key: 'securityAlerts' as const,
      label: 'Security Alerts',
      description: 'Get notified about security events and suspicious activity',
    },
    {
      key: 'maintenanceAlerts' as const,
      label: 'Maintenance Alerts',
      description: 'Get notified about scheduled maintenance windows',
    },
    {
      key: 'weeklyDigest' as const,
      label: 'Weekly Digest',
      description: 'Receive a weekly summary of network activity',
    },
  ]

  return (
    <form onSubmit={handleSave} className="space-y-6 max-w-lg">
      <div className="space-y-4">
        {notificationOptions.map(option => (
          <div
            key={option.key}
            className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-800 rounded-lg"
          >
            <div>
              <label
                htmlFor={option.key}
                className="font-medium text-gray-900 dark:text-gray-100 cursor-pointer"
              >
                {option.label}
              </label>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                {option.description}
              </p>
            </div>
            <button
              type="button"
              id={option.key}
              role="switch"
              aria-checked={settings[option.key]}
              onClick={() => toggleSetting(option.key)}
              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                settings[option.key] ? 'bg-blue-600' : 'bg-gray-300 dark:bg-gray-600'
              }`}
            >
              <span
                className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                  settings[option.key] ? 'translate-x-6' : 'translate-x-1'
                }`}
              />
            </button>
          </div>
        ))}
      </div>

      <div>
        <button type="submit" disabled={saving} className="btn btn-primary">
          {saving ? 'Saving...' : 'Save Changes'}
        </button>
      </div>
    </form>
  )
}

function AppearanceTab() {
  const { theme, setTheme, resolvedTheme } = useTheme()

  const themes: { id: 'light' | 'dark' | 'system'; label: string; description: string; icon: string }[] = [
    { id: 'light', label: 'Light', description: 'Light background with dark text', icon: '☀️' },
    { id: 'dark', label: 'Dark', description: 'Dark background with light text', icon: '🌙' },
    { id: 'system', label: 'System', description: 'Follow your system preference', icon: '💻' },
  ]

  return (
    <div className="space-y-6 max-w-lg">
      <div>
        <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-4">
          Theme
        </h3>
        <div className="grid grid-cols-1 gap-4">
          {themes.map(t => (
            <button
              key={t.id}
              type="button"
              onClick={() => setTheme(t.id)}
              className={`flex items-center p-4 rounded-lg border-2 transition-colors text-left ${
                theme === t.id
                  ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20'
                  : 'border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600'
              }`}
            >
              <span className="text-2xl mr-4">{t.icon}</span>
              <div className="flex-1">
                <p className="font-medium text-gray-900 dark:text-gray-100">
                  {t.label}
                </p>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  {t.description}
                </p>
              </div>
              {theme === t.id && (
                <svg className="w-5 h-5 text-blue-500" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                </svg>
              )}
            </button>
          ))}
        </div>
        <p className="mt-4 text-sm text-gray-500 dark:text-gray-400">
          Current theme: <span className="font-medium">{resolvedTheme}</span>
          {theme === 'system' && ' (based on system preference)'}
        </p>
      </div>

      <div className="pt-6 border-t border-gray-200 dark:border-gray-700">
        <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-4">
          Display Settings
        </h3>
        <div className="space-y-4">
          <div className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
            <div>
              <p className="font-medium text-gray-900 dark:text-gray-100">Compact Mode</p>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                Reduce spacing for denser information display
              </p>
            </div>
            <button
              type="button"
              role="switch"
              aria-checked={false}
              className="relative inline-flex h-6 w-11 items-center rounded-full bg-gray-300 dark:bg-gray-600"
            >
              <span className="inline-block h-4 w-4 transform rounded-full bg-white translate-x-1" />
            </button>
          </div>

          <div className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
            <div>
              <p className="font-medium text-gray-900 dark:text-gray-100">Animations</p>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                Enable smooth transitions and animations
              </p>
            </div>
            <button
              type="button"
              role="switch"
              aria-checked={true}
              className="relative inline-flex h-6 w-11 items-center rounded-full bg-blue-600"
            >
              <span className="inline-block h-4 w-4 transform rounded-full bg-white translate-x-6" />
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

function ApiKeysTab() {
  const { data, loading, refetch } = useQuery(GET_API_KEYS)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [showRevokeModal, setShowRevokeModal] = useState<string | null>(null)
  const [newKeyName, setNewKeyName] = useState('')
  const [newKeyExpiry, setNewKeyExpiry] = useState('30')
  const [createdKey, setCreatedKey] = useState<string | null>(null)

  const [createApiKey, { loading: creating }] = useMutation(CREATE_API_KEY, {
    onCompleted: (data) => {
      setCreatedKey(data.createApiKey.key)
      setShowCreateModal(false)
      setNewKeyName('')
      refetch()
      toast.success('API key created successfully')
    },
    onError: (error) => {
      toast.error(error.message || 'Failed to create API key')
    },
  })

  const [revokeApiKey, { loading: revoking }] = useMutation(REVOKE_API_KEY, {
    onCompleted: () => {
      setShowRevokeModal(null)
      refetch()
      toast.success('API key revoked successfully')
    },
    onError: (error) => {
      toast.error(error.message || 'Failed to revoke API key')
    },
  })

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!newKeyName.trim()) {
      toast.error('Please enter a name for the API key')
      return
    }
    await createApiKey({
      variables: {
        input: {
          name: newKeyName,
          expiresInDays: parseInt(newKeyExpiry),
        },
      },
    })
  }

  const handleRevoke = async () => {
    if (showRevokeModal) {
      await revokeApiKey({ variables: { id: showRevokeModal } })
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    toast.success('Copied to clipboard')
  }

  const apiKeys: ApiKey[] = data?.apiKeys || []

  if (loading) {
    return <LoadingSkeleton rows={4} />
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100">
            API Keys
          </h3>
          <p className="text-sm text-gray-500 dark:text-gray-400">
            Manage API keys for programmatic access to Patronus
          </p>
        </div>
        <button
          type="button"
          onClick={() => setShowCreateModal(true)}
          className="btn btn-primary"
        >
          Create API Key
        </button>
      </div>

      {createdKey && (
        <div className="p-4 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg">
          <div className="flex items-start justify-between">
            <div>
              <p className="font-medium text-green-800 dark:text-green-200">
                API Key Created Successfully
              </p>
              <p className="text-sm text-green-700 dark:text-green-300 mt-1">
                Copy this key now. You won't be able to see it again.
              </p>
            </div>
            <button
              type="button"
              onClick={() => setCreatedKey(null)}
              className="text-green-800 dark:text-green-200 hover:text-green-900 dark:hover:text-green-100"
            >
              ×
            </button>
          </div>
          <div className="mt-3 flex items-center gap-2">
            <code className="flex-1 p-2 bg-green-100 dark:bg-green-900 rounded text-sm font-mono text-green-900 dark:text-green-100 overflow-x-auto">
              {createdKey}
            </code>
            <button
              type="button"
              onClick={() => copyToClipboard(createdKey)}
              className="btn btn-secondary btn-sm"
            >
              Copy
            </button>
          </div>
        </div>
      )}

      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead className="bg-gray-50 dark:bg-gray-800">
            <tr>
              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Name
              </th>
              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Key Prefix
              </th>
              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Created
              </th>
              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Last Used
              </th>
              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Expires
              </th>
              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Status
              </th>
              <th scope="col" className="relative px-6 py-3">
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
            {apiKeys.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-6 py-12 text-center text-gray-500 dark:text-gray-400">
                  No API keys found. Create one to get started.
                </td>
              </tr>
            ) : (
              apiKeys.map((key) => (
                <tr key={key.id} className="hover:bg-gray-50 dark:hover:bg-gray-800">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm font-medium text-gray-900 dark:text-gray-100">
                      {key.name}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <code className="text-sm text-gray-500 dark:text-gray-400 font-mono">
                      {key.prefix}...
                    </code>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                    {dayjs(key.createdAt).format('MMM D, YYYY')}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                    {key.lastUsed ? dayjs(key.lastUsed).fromNow() : 'Never'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                    {key.expiresAt ? dayjs(key.expiresAt).format('MMM D, YYYY') : 'Never'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`badge ${
                      key.revoked ? 'badge-danger' :
                      key.expiresAt && dayjs(key.expiresAt).isBefore(dayjs()) ? 'badge-warning' :
                      'badge-success'
                    }`}>
                      {key.revoked ? 'Revoked' :
                       key.expiresAt && dayjs(key.expiresAt).isBefore(dayjs()) ? 'Expired' :
                       'Active'}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    {!key.revoked && (
                      <button
                        type="button"
                        onClick={() => setShowRevokeModal(key.id)}
                        className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300"
                      >
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Create Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex min-h-full items-end justify-center p-4 text-center sm:items-center sm:p-0">
            <div className="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" onClick={() => setShowCreateModal(false)} />
            <div className="relative transform overflow-hidden rounded-lg bg-white dark:bg-gray-800 text-left shadow-xl transition-all sm:my-8 sm:w-full sm:max-w-lg">
              <form onSubmit={handleCreate}>
                <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                  <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100">
                    Create API Key
                  </h3>
                </div>
                <div className="px-6 py-4 space-y-4">
                  <div>
                    <label htmlFor="key-name" className="label">Key Name</label>
                    <input
                      id="key-name"
                      type="text"
                      className="input"
                      value={newKeyName}
                      onChange={(e) => setNewKeyName(e.target.value)}
                      placeholder="e.g., CI/CD Pipeline"
                      required
                    />
                  </div>
                  <div>
                    <label htmlFor="key-expiry" className="label">Expiration</label>
                    <select
                      id="key-expiry"
                      className="input"
                      value={newKeyExpiry}
                      onChange={(e) => setNewKeyExpiry(e.target.value)}
                    >
                      <option value="7">7 days</option>
                      <option value="30">30 days</option>
                      <option value="90">90 days</option>
                      <option value="365">1 year</option>
                      <option value="0">Never</option>
                    </select>
                  </div>
                </div>
                <div className="px-6 py-4 bg-gray-50 dark:bg-gray-900 flex justify-end gap-3">
                  <button
                    type="button"
                    onClick={() => setShowCreateModal(false)}
                    className="btn btn-secondary"
                  >
                    Cancel
                  </button>
                  <button type="submit" disabled={creating} className="btn btn-primary">
                    {creating ? 'Creating...' : 'Create Key'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Revoke Confirmation */}
      <ConfirmModal
        isOpen={!!showRevokeModal}
        onClose={() => setShowRevokeModal(null)}
        onConfirm={handleRevoke}
        title="Revoke API Key"
        message="Are you sure you want to revoke this API key? This action cannot be undone and any applications using this key will lose access."
        confirmText="Revoke"
        type="danger"
        loading={revoking}
      />
    </div>
  )
}

function SystemInfoTab() {
  const { data, loading, error } = useQuery(GET_SYSTEM_INFO, {
    pollInterval: 30000, // Refresh every 30 seconds
  })

  if (loading) {
    return <LoadingSkeleton rows={6} />
  }

  if (error) {
    return (
      <div className="text-center py-12">
        <p className="text-red-500">Failed to load system information</p>
        <p className="text-sm text-gray-500 mt-2">{error.message}</p>
      </div>
    )
  }

  const systemInfo: SystemInfo = data?.systemInfo || {
    version: 'Unknown',
    buildDate: 'Unknown',
    rustVersion: 'Unknown',
    uptime: 0,
    cpuUsage: 0,
    memoryUsage: 0,
    memoryTotal: 0,
    diskUsage: 0,
    diskTotal: 0,
    activeSessions: 0,
    totalSites: 0,
    totalPolicies: 0,
  }

  const formatUptime = (seconds: number): string => {
    const days = Math.floor(seconds / 86400)
    const hours = Math.floor((seconds % 86400) / 3600)
    const minutes = Math.floor((seconds % 3600) / 60)

    const parts = []
    if (days > 0) parts.push(`${days}d`)
    if (hours > 0) parts.push(`${hours}h`)
    if (minutes > 0) parts.push(`${minutes}m`)
    return parts.join(' ') || '< 1m'
  }

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  const getUsageColor = (percentage: number): string => {
    if (percentage >= 90) return 'bg-red-500'
    if (percentage >= 70) return 'bg-yellow-500'
    return 'bg-green-500'
  }

  return (
    <div className="space-y-6">
      {/* Version Info */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
          <p className="text-sm text-gray-500 dark:text-gray-400">Version</p>
          <p className="text-lg font-semibold text-gray-900 dark:text-gray-100">
            {systemInfo.version}
          </p>
        </div>
        <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
          <p className="text-sm text-gray-500 dark:text-gray-400">Build Date</p>
          <p className="text-lg font-semibold text-gray-900 dark:text-gray-100">
            {systemInfo.buildDate}
          </p>
        </div>
        <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
          <p className="text-sm text-gray-500 dark:text-gray-400">Rust Version</p>
          <p className="text-lg font-semibold text-gray-900 dark:text-gray-100">
            {systemInfo.rustVersion}
          </p>
        </div>
      </div>

      {/* Uptime & Sessions */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
          <p className="text-sm text-gray-500 dark:text-gray-400">Uptime</p>
          <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
            {formatUptime(systemInfo.uptime)}
          </p>
        </div>
        <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
          <p className="text-sm text-gray-500 dark:text-gray-400">Active Sessions</p>
          <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
            {systemInfo.activeSessions}
          </p>
        </div>
      </div>

      {/* Resource Usage */}
      <div>
        <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-4">
          Resource Usage
        </h3>
        <div className="space-y-4">
          <div>
            <div className="flex justify-between mb-1">
              <span className="text-sm text-gray-600 dark:text-gray-400">CPU</span>
              <span className="text-sm font-medium text-gray-900 dark:text-gray-100">
                {systemInfo.cpuUsage.toFixed(1)}%
              </span>
            </div>
            <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2.5">
              <div
                className={`h-2.5 rounded-full transition-all ${getUsageColor(systemInfo.cpuUsage)}`}
                style={{ width: `${Math.min(systemInfo.cpuUsage, 100)}%` }}
              />
            </div>
          </div>

          <div>
            <div className="flex justify-between mb-1">
              <span className="text-sm text-gray-600 dark:text-gray-400">Memory</span>
              <span className="text-sm font-medium text-gray-900 dark:text-gray-100">
                {formatBytes(systemInfo.memoryUsage)} / {formatBytes(systemInfo.memoryTotal)}
                {' '}({((systemInfo.memoryUsage / systemInfo.memoryTotal) * 100).toFixed(1)}%)
              </span>
            </div>
            <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2.5">
              <div
                className={`h-2.5 rounded-full transition-all ${getUsageColor((systemInfo.memoryUsage / systemInfo.memoryTotal) * 100)}`}
                style={{ width: `${(systemInfo.memoryUsage / systemInfo.memoryTotal) * 100}%` }}
              />
            </div>
          </div>

          <div>
            <div className="flex justify-between mb-1">
              <span className="text-sm text-gray-600 dark:text-gray-400">Disk</span>
              <span className="text-sm font-medium text-gray-900 dark:text-gray-100">
                {formatBytes(systemInfo.diskUsage)} / {formatBytes(systemInfo.diskTotal)}
                {' '}({((systemInfo.diskUsage / systemInfo.diskTotal) * 100).toFixed(1)}%)
              </span>
            </div>
            <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2.5">
              <div
                className={`h-2.5 rounded-full transition-all ${getUsageColor((systemInfo.diskUsage / systemInfo.diskTotal) * 100)}`}
                style={{ width: `${(systemInfo.diskUsage / systemInfo.diskTotal) * 100}%` }}
              />
            </div>
          </div>
        </div>
      </div>

      {/* Network Stats */}
      <div>
        <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-4">
          Network Statistics
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
            <p className="text-sm text-gray-500 dark:text-gray-400">Total Sites</p>
            <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
              {systemInfo.totalSites}
            </p>
          </div>
          <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
            <p className="text-sm text-gray-500 dark:text-gray-400">Total Policies</p>
            <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
              {systemInfo.totalPolicies}
            </p>
          </div>
        </div>
      </div>

      {/* Maintenance Actions */}
      <div className="pt-6 border-t border-gray-200 dark:border-gray-700">
        <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-4">
          Maintenance
        </h3>
        <div className="flex flex-wrap gap-3">
          <button type="button" className="btn btn-secondary">
            Download Logs
          </button>
          <button type="button" className="btn btn-secondary">
            Export Configuration
          </button>
          <button type="button" className="btn btn-secondary">
            Health Check
          </button>
          <button type="button" className="btn btn-danger">
            Restart Services
          </button>
        </div>
      </div>
    </div>
  )
}
