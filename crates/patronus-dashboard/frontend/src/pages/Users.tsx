import { useState } from 'react'
import { useQuery, useMutation } from '@apollo/client'
import {
  GET_USERS,
  CREATE_USER,
  UPDATE_USER,
  DELETE_USER,
} from '../graphql/queries'
import type { User, CreateUserInput, UpdateUserInput } from '../types'
import toast from 'react-hot-toast'
import { PlusIcon, PencilIcon, TrashIcon } from '@heroicons/react/24/outline'
import dayjs from 'dayjs'

export default function Users() {
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [editingUser, setEditingUser] = useState<User | null>(null)

  const { data, loading, refetch } = useQuery(GET_USERS)
  const [createUser] = useMutation(CREATE_USER)
  const [updateUser] = useMutation(UPDATE_USER)
  const [deleteUser] = useMutation(DELETE_USER)

  const users: User[] = data?.users || []

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

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this user?')) return

    try {
      await deleteUser({ variables: { id } })
      toast.success('User deleted successfully')
      refetch()
    } catch (err: any) {
      toast.error(err.message || 'Failed to delete user')
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100">
            Users
          </h1>
          <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
            Manage user accounts and permissions
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="btn btn-primary flex items-center"
        >
          <PlusIcon className="w-5 h-5 mr-2" />
          Add User
        </button>
      </div>

      <div className="card">
        {loading ? (
          <div className="flex justify-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500" />
          </div>
        ) : users.length === 0 ? (
          <div className="text-center py-12">
            <p className="text-gray-500 dark:text-gray-400 mb-4">
              No users found
            </p>
            <button
              onClick={() => setShowCreateModal(true)}
              className="btn btn-primary"
            >
              Create your first user
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead>
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Email
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
                {users.map((user) => (
                  <tr key={user.id}>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-gray-100">
                      {user.email}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <RoleBadge role={user.role} />
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span
                        className={`badge ${
                          user.active ? 'badge-success' : 'badge-danger'
                        }`}
                      >
                        {user.active ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {dayjs(user.createdAt).format('MMM D, YYYY')}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {user.lastLogin
                        ? dayjs(user.lastLogin).format('MMM D, YYYY HH:mm')
                        : 'Never'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm space-x-2">
                      <button
                        onClick={() => setEditingUser(user)}
                        className="text-blue-600 hover:text-blue-900 dark:text-blue-400 dark:hover:text-blue-300"
                      >
                        <PencilIcon className="w-5 h-5 inline" />
                      </button>
                      <button
                        onClick={() => handleDelete(user.id)}
                        className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300"
                      >
                        <TrashIcon className="w-5 h-5 inline" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {showCreateModal && (
        <UserModal
          onClose={() => setShowCreateModal(false)}
          onSubmit={handleCreate}
        />
      )}

      {editingUser && (
        <UserModal
          user={editingUser}
          onClose={() => setEditingUser(null)}
          onSubmit={(input) => handleUpdate(editingUser.id, input)}
        />
      )}
    </div>
  )
}

function RoleBadge({ role }: { role: string }) {
  const roleClasses = {
    Admin: 'badge-danger',
    Operator: 'badge-warning',
    Viewer: 'badge-info',
  }

  return (
    <span className={`badge ${roleClasses[role as keyof typeof roleClasses]}`}>
      {role}
    </span>
  )
}

function UserModal({
  user,
  onClose,
  onSubmit,
}: {
  user?: User
  onClose: () => void
  onSubmit: (input: CreateUserInput | UpdateUserInput) => void
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
      // Update
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
      // Create
      if (!password) {
        alert('Password is required')
        return
      }
      onSubmit({ email, password, role, active })
    }
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md w-full">
        <h2 className="text-xl font-bold text-gray-900 dark:text-gray-100 mb-4">
          {user ? 'Edit User' : 'Create User'}
        </h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="email" className="label">
              Email
            </label>
            <input
              id="email"
              type="email"
              required
              className="input"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>
          <div>
            <label htmlFor="password" className="label">
              Password {user && '(leave blank to keep unchanged)'}
            </label>
            <input
              id="password"
              type="password"
              required={!user}
              className="input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={user ? 'Leave blank to keep current' : ''}
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
              <option value="Viewer">Viewer</option>
              <option value="Operator">Operator</option>
              <option value="Admin">Admin</option>
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
              className="btn btn-secondary"
            >
              Cancel
            </button>
            <button type="submit" className="btn btn-primary">
              {user ? 'Update' : 'Create'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
