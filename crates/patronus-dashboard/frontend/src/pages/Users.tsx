import { useState, useMemo } from 'react'
import { useQuery, useMutation } from '@apollo/client'
import {
  GET_USERS,
  CREATE_USER,
  UPDATE_USER,
  DELETE_USER,
  DEACTIVATE_USER,
  GET_AUDIT_LOGS,
} from '../graphql/queries'
import type { User, CreateUserInput, UpdateUserInput, AuditLog } from '../types'
import toast from 'react-hot-toast'
import {
  PlusIcon,
  PencilIcon,
  TrashIcon,
  EyeIcon,
  FunnelIcon,
  XMarkIcon,
  ShieldCheckIcon,
  ClockIcon,
  UserCircleIcon,
  NoSymbolIcon,
} from '@heroicons/react/24/outline'
import dayjs from 'dayjs'
import relativeTime from 'dayjs/plugin/relativeTime'
import Loading from '../components/Loading'
import SearchInput from '../components/SearchInput'
import Pagination from '../components/Pagination'
import ConfirmModal from '../components/ConfirmModal'
import EmptyState from '../components/EmptyState'
import { RoleBadge } from '../components/StatusBadge'
import { useAuth } from '../hooks/useAuth'

dayjs.extend(relativeTime)

export default function Users() {
  const { user: currentUser } = useAuth()
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [editingUser, setEditingUser] = useState<User | null>(null)
  const [viewingUser, setViewingUser] = useState<User | null>(null)
  const [deletingUser, setDeletingUser] = useState<User | null>(null)
  const [deactivatingUser, setDeactivatingUser] = useState<User | null>(null)
  const [search, setSearch] = useState('')
  const [roleFilter, setRoleFilter] = useState<string>('')
  const [statusFilter, setStatusFilter] = useState<string>('')
  const [page, setPage] = useState(1)
  const [itemsPerPage, setItemsPerPage] = useState(10)

  const { data, loading, refetch } = useQuery(GET_USERS)
  const [createUser, { loading: creating }] = useMutation(CREATE_USER)
  const [updateUser, { loading: updating }] = useMutation(UPDATE_USER)
  const [deleteUser, { loading: deleting }] = useMutation(DELETE_USER)
  const [deactivateUser, { loading: deactivating }] = useMutation(DEACTIVATE_USER)

  const users: User[] = data?.users || []

  // Filter and search users
  const filteredUsers = useMemo(() => {
    return users.filter((user) => {
      const matchesSearch = !search || user.email.toLowerCase().includes(search.toLowerCase())
      const matchesRole = !roleFilter || user.role === roleFilter
      const matchesStatus =
        !statusFilter ||
        (statusFilter === 'active' && user.active) ||
        (statusFilter === 'inactive' && !user.active)
      return matchesSearch && matchesRole && matchesStatus
    })
  }, [users, search, roleFilter, statusFilter])

  // Pagination
  const totalPages = Math.ceil(filteredUsers.length / itemsPerPage)
  const paginatedUsers = filteredUsers.slice(
    (page - 1) * itemsPerPage,
    page * itemsPerPage
  )

  // Stats
  const adminCount = users.filter((u) => u.role === 'Admin').length
  const operatorCount = users.filter((u) => u.role === 'Operator').length
  const viewerCount = users.filter((u) => u.role === 'Viewer').length
  const activeCount = users.filter((u) => u.active).length

  const handleCreate = async (input: CreateUserInput) => {
    try {
      await createUser({ variables: { input } })
      toast.success('User created successfully')
      setShowCreateModal(false)
      refetch()
    } catch (err: any) {
      toast.error(err.message || 'Failed to create user')
    }
  }

  const handleUpdate = async (id: string, input: UpdateUserInput) => {
    try {
      await updateUser({ variables: { id, input } })
      toast.success('User updated successfully')
      setEditingUser(null)
      refetch()
    } catch (err: any) {
      toast.error(err.message || 'Failed to update user')
    }
  }

  const handleDelete = async () => {
    if (!deletingUser) return

    try {
      await deleteUser({ variables: { id: deletingUser.id } })
      toast.success('User deleted successfully')
      setDeletingUser(null)
      refetch()
    } catch (err: any) {
      toast.error(err.message || 'Failed to delete user')
    }
  }

  const handleDeactivate = async () => {
    if (!deactivatingUser) return

    try {
      await deactivateUser({ variables: { userId: deactivatingUser.id } })
      toast.success('User deactivated successfully')
      setDeactivatingUser(null)
      refetch()
    } catch (err: any) {
      toast.error(err.message || 'Failed to deactivate user')
    }
  }

  const clearFilters = () => {
    setSearch('')
    setRoleFilter('')
    setStatusFilter('')
    setPage(1)
  }

  const hasFilters = search || roleFilter || statusFilter

  if (loading) {
    return <Loading message="Loading users..." />
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100">
            Users
          </h1>
          <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
            Manage user accounts and permissions ({filteredUsers.length} of {users.length})
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="mt-4 md:mt-0 btn btn-primary flex items-center"
        >
          <PlusIcon className="w-5 h-5 mr-2" />
          Add User
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <StatCard title="Total Users" value={users.length} />
        <StatCard title="Active" value={activeCount} color="green" />
        <StatCard title="Admins" value={adminCount} color="red" />
        <StatCard title="Operators" value={operatorCount} color="yellow" />
        <StatCard title="Viewers" value={viewerCount} color="blue" />
      </div>

      {/* Filters */}
      <div className="card">
        <div className="flex flex-col md:flex-row md:items-center gap-4">
          <SearchInput
            value={search}
            onChange={setSearch}
            placeholder="Search users..."
            className="flex-1"
          />
          <div className="flex items-center gap-4 flex-wrap">
            <div className="flex items-center gap-2">
              <FunnelIcon className="w-5 h-5 text-gray-400" />
              <select
                value={roleFilter}
                onChange={(e) => {
                  setRoleFilter(e.target.value)
                  setPage(1)
                }}
                className="input w-32"
                aria-label="Filter by role"
              >
                <option value="">All Roles</option>
                <option value="Admin">Admin</option>
                <option value="Operator">Operator</option>
                <option value="Viewer">Viewer</option>
              </select>
            </div>
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value)
                setPage(1)
              }}
              className="input w-32"
              aria-label="Filter by status"
            >
              <option value="">All Status</option>
              <option value="active">Active</option>
              <option value="inactive">Inactive</option>
            </select>
            {hasFilters && (
              <button
                onClick={clearFilters}
                className="text-sm text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 flex items-center"
              >
                <XMarkIcon className="w-4 h-4 mr-1" />
                Clear
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Users Table */}
      <div className="card">
        {paginatedUsers.length === 0 ? (
          <EmptyState
            title={hasFilters ? 'No users match your filters' : 'No users found'}
            description={
              hasFilters
                ? 'Try adjusting your search or filters'
                : 'Create your first user to get started'
            }
            action={
              hasFilters ? (
                <button onClick={clearFilters} className="btn btn-secondary">
                  Clear Filters
                </button>
              ) : (
                <button
                  onClick={() => setShowCreateModal(true)}
                  className="btn btn-primary"
                >
                  Create your first user
                </button>
              )
            }
          />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                <thead>
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      User
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Role
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Created
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Last Login
                    </th>
                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                  {paginatedUsers.map((user) => {
                    const isSelf = currentUser?.id === user.id
                    return (
                      <tr key={user.id} className={`hover:bg-gray-50 dark:hover:bg-gray-700/50 ${!user.active ? 'opacity-60' : ''}`}>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center">
                            <div className="w-8 h-8 rounded-full bg-gray-200 dark:bg-gray-600 flex items-center justify-center text-gray-500 dark:text-gray-300 mr-3">
                              <UserCircleIcon className="w-6 h-6" />
                            </div>
                            <div>
                              <p className="text-sm font-medium text-gray-900 dark:text-gray-100">
                                {user.email}
                                {isSelf && (
                                  <span className="ml-2 text-xs text-gray-500 dark:text-gray-400">(you)</span>
                                )}
                              </p>
                              <p className="text-xs text-gray-500 dark:text-gray-400">
                                ID: {user.id.slice(0, 8)}...
                              </p>
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <RoleBadge role={user.role} />
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span
                            className={`badge ${user.active ? 'badge-success' : 'badge-danger'}`}
                          >
                            {user.active ? 'Active' : 'Inactive'}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                          {dayjs(user.createdAt).format('MMM D, YYYY')}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                          {user.lastLogin ? (
                            <span title={dayjs(user.lastLogin).format('YYYY-MM-DD HH:mm:ss')}>
                              {dayjs(user.lastLogin).fromNow()}
                            </span>
                          ) : (
                            <span className="text-gray-400">Never</span>
                          )}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-right text-sm space-x-2">
                          <button
                            onClick={() => setViewingUser(user)}
                            className="text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-200"
                            title="View details"
                          >
                            <EyeIcon className="w-5 h-5 inline" />
                          </button>
                          <button
                            onClick={() => setEditingUser(user)}
                            className="text-blue-600 hover:text-blue-900 dark:text-blue-400 dark:hover:text-blue-300"
                            title="Edit user"
                            disabled={isSelf}
                          >
                            <PencilIcon className="w-5 h-5 inline" />
                          </button>
                          {user.active && !isSelf && (
                            <button
                              onClick={() => setDeactivatingUser(user)}
                              className="text-yellow-600 hover:text-yellow-900 dark:text-yellow-400 dark:hover:text-yellow-300"
                              title="Deactivate user"
                            >
                              <NoSymbolIcon className="w-5 h-5 inline" />
                            </button>
                          )}
                          {!isSelf && (
                            <button
                              onClick={() => setDeletingUser(user)}
                              className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300"
                              title="Delete user"
                            >
                              <TrashIcon className="w-5 h-5 inline" />
                            </button>
                          )}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
            <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
              <Pagination
                currentPage={page}
                totalPages={totalPages}
                totalItems={filteredUsers.length}
                itemsPerPage={itemsPerPage}
                onPageChange={setPage}
                onItemsPerPageChange={(n) => {
                  setItemsPerPage(n)
                  setPage(1)
                }}
              />
            </div>
          </>
        )}
      </div>

      {/* Create Modal */}
      {showCreateModal && (
        <UserModal
          onClose={() => setShowCreateModal(false)}
          onSubmit={handleCreate}
          loading={creating}
        />
      )}

      {/* Edit Modal */}
      {editingUser && (
        <UserModal
          user={editingUser}
          onClose={() => setEditingUser(null)}
          onSubmit={(input) => handleUpdate(editingUser.id, input)}
          loading={updating}
        />
      )}

      {/* View Modal */}
      {viewingUser && (
        <UserDetailModal
          user={viewingUser}
          onClose={() => setViewingUser(null)}
          onEdit={() => {
            setEditingUser(viewingUser)
            setViewingUser(null)
          }}
        />
      )}

      {/* Delete Confirmation */}
      <ConfirmModal
        isOpen={!!deletingUser}
        onClose={() => setDeletingUser(null)}
        onConfirm={handleDelete}
        title="Delete User"
        message={`Are you sure you want to delete "${deletingUser?.email}"? This action cannot be undone.`}
        confirmText="Delete"
        variant="danger"
        loading={deleting}
      />

      {/* Deactivate Confirmation */}
      <ConfirmModal
        isOpen={!!deactivatingUser}
        onClose={() => setDeactivatingUser(null)}
        onConfirm={handleDeactivate}
        title="Deactivate User"
        message={`Are you sure you want to deactivate "${deactivatingUser?.email}"? They will no longer be able to log in.`}
        confirmText="Deactivate"
        variant="warning"
        loading={deactivating}
      />
    </div>
  )
}

function StatCard({
  title,
  value,
  color,
}: {
  title: string
  value: number
  color?: 'green' | 'yellow' | 'red' | 'blue'
}) {
  const colorClasses = {
    green: 'text-green-600 dark:text-green-400',
    yellow: 'text-yellow-600 dark:text-yellow-400',
    red: 'text-red-600 dark:text-red-400',
    blue: 'text-blue-600 dark:text-blue-400',
  }

  return (
    <div className="card">
      <p className="text-sm text-gray-500 dark:text-gray-400">{title}</p>
      <p className={`text-2xl font-bold ${color ? colorClasses[color] : 'text-gray-900 dark:text-gray-100'}`}>
        {value}
      </p>
    </div>
  )
}

function UserModal({
  user,
  onClose,
  onSubmit,
  loading,
}: {
  user?: User
  onClose: () => void
  onSubmit: (input: CreateUserInput | UpdateUserInput) => void
  loading?: boolean
}) {
  const [email, setEmail] = useState(user?.email || '')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState<'Admin' | 'Operator' | 'Viewer'>(
    user?.role || 'Viewer'
  )
  const [active, setActive] = useState(user?.active ?? true)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    if (user) {
      const input: UpdateUserInput = {
        email,
        role,
        active,
      }
      if (password) {
        input.password = password
      }
      onSubmit(input)
    } else {
      if (!password) {
        toast.error('Password is required')
        return
      }
      onSubmit({ email, password, role, active })
    }
  }

  return (
    <div
      className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
    >
      <div
        className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="text-xl font-bold text-gray-900 dark:text-gray-100 mb-4">
          {user ? 'Edit User' : 'Create User'}
        </h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="email" className="label">
              Email <span className="text-red-500">*</span>
            </label>
            <input
              id="email"
              type="email"
              required
              className="input"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="user@example.com"
            />
          </div>
          <div>
            <label htmlFor="password" className="label">
              Password {user ? '(leave blank to keep unchanged)' : <span className="text-red-500">*</span>}
            </label>
            <input
              id="password"
              type="password"
              required={!user}
              className="input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={user ? 'Leave blank to keep current' : 'Minimum 8 characters'}
            />
          </div>
          <div>
            <label htmlFor="role" className="label">
              Role
            </label>
            <select
              id="role"
              className="input"
              value={role}
              onChange={(e) => setRole(e.target.value as any)}
            >
              <option value="Viewer">Viewer - Read-only access</option>
              <option value="Operator">Operator - Manage sites and policies</option>
              <option value="Admin">Admin - Full access</option>
            </select>
          </div>
          <div className="flex items-center">
            <input
              id="active"
              type="checkbox"
              className="w-4 h-4 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500"
              checked={active}
              onChange={(e) => setActive(e.target.checked)}
            />
            <label
              htmlFor="active"
              className="ml-2 text-sm font-medium text-gray-900 dark:text-gray-100"
            >
              Active
            </label>
          </div>
          <div className="flex justify-end space-x-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              disabled={loading}
              className="btn btn-secondary"
            >
              Cancel
            </button>
            <button type="submit" disabled={loading} className="btn btn-primary">
              {loading ? 'Saving...' : user ? 'Update' : 'Create'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function UserDetailModal({
  user,
  onClose,
  onEdit,
}: {
  user: User
  onClose: () => void
  onEdit: () => void
}) {
  const { data: auditData, loading: auditLoading } = useQuery(GET_AUDIT_LOGS, {
    variables: { userId: user.id, limit: 10 },
  })

  const auditLogs: AuditLog[] = auditData?.auditLogs || []

  return (
    <div
      className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
    >
      <div
        className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between mb-6">
          <div className="flex items-center">
            <div className="w-12 h-12 rounded-full bg-gray-200 dark:bg-gray-600 flex items-center justify-center text-gray-500 dark:text-gray-300 mr-4">
              <UserCircleIcon className="w-8 h-8" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-gray-900 dark:text-gray-100">
                {user.email}
              </h2>
              <div className="flex items-center mt-1 space-x-2">
                <RoleBadge role={user.role} />
                <span
                  className={`badge ${user.active ? 'badge-success' : 'badge-danger'}`}
                >
                  {user.active ? 'Active' : 'Inactive'}
                </span>
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
            aria-label="Close"
          >
            <XMarkIcon className="w-6 h-6" />
          </button>
        </div>

        {/* User Info */}
        <div className="grid grid-cols-2 gap-4 mb-6">
          <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4">
            <div className="flex items-center text-gray-500 dark:text-gray-400 mb-1">
              <ShieldCheckIcon className="w-4 h-4 mr-2" />
              <span className="text-sm">Role</span>
            </div>
            <p className="text-lg font-medium text-gray-900 dark:text-gray-100">{user.role}</p>
          </div>
          <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4">
            <div className="flex items-center text-gray-500 dark:text-gray-400 mb-1">
              <ClockIcon className="w-4 h-4 mr-2" />
              <span className="text-sm">Last Login</span>
            </div>
            <p className="text-lg font-medium text-gray-900 dark:text-gray-100">
              {user.lastLogin ? dayjs(user.lastLogin).format('MMM D, YYYY HH:mm') : 'Never'}
            </p>
          </div>
        </div>

        <p className="text-sm text-gray-500 dark:text-gray-400 mb-6">
          Created {dayjs(user.createdAt).format('MMMM D, YYYY [at] HH:mm')}
        </p>

        {/* Audit Logs */}
        <div className="mb-6">
          <h3 className="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-3">
            Recent Activity
          </h3>
          {auditLoading ? (
            <div className="flex justify-center py-4">
              <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500" />
            </div>
          ) : auditLogs.length > 0 ? (
            <div className="space-y-2 max-h-60 overflow-y-auto">
              {auditLogs.map((log) => (
                <div
                  key={log.id}
                  className="flex items-start justify-between p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
                >
                  <div>
                    <p className="text-sm text-gray-900 dark:text-gray-100">{log.description}</p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">{log.ipAddress}</p>
                  </div>
                  <span className="text-xs text-gray-500 dark:text-gray-400 whitespace-nowrap ml-4">
                    {dayjs(log.timestamp).fromNow()}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-gray-500 dark:text-gray-400 text-center py-4">
              No activity recorded
            </p>
          )}
        </div>

        {/* Actions */}
        <div className="flex justify-end space-x-3">
          <button onClick={onClose} className="btn btn-secondary">
            Close
          </button>
          <button onClick={onEdit} className="btn btn-primary">
            Edit User
          </button>
        </div>
      </div>
    </div>
  )
}
