import { useState } from 'react'
import { useQuery, useMutation } from '@apollo/client'
import {
  GET_POLICIES,
  CREATE_POLICY,
  UPDATE_POLICY,
  DELETE_POLICY,
} from '../graphql/queries'
import type { Policy, CreatePolicyInput, UpdatePolicyInput } from '../types'
import toast from 'react-hot-toast'
import { PlusIcon, PencilIcon, TrashIcon } from '@heroicons/react/24/outline'
import dayjs from 'dayjs'

export default function Policies() {
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [editingPolicy, setEditingPolicy] = useState<Policy | null>(null)

  const { data, loading, refetch } = useQuery(GET_POLICIES)
  const [createPolicy] = useMutation(CREATE_POLICY)
  const [updatePolicy] = useMutation(UPDATE_POLICY)
  const [deletePolicy] = useMutation(DELETE_POLICY)

  const policies: Policy[] = data?.policies || []

  const handleCreate = async (input: CreatePolicyInput) => {
    try {
      await createPolicy({ variables: { input } })
      toast.success('Policy created successfully')
      setShowCreateModal(false)
      refetch()
    } catch (err: any) {
      toast.error(err.message || 'Failed to create policy')
    }
  }

  const handleUpdate = async (id: string, input: UpdatePolicyInput) => {
    try {
      await updatePolicy({ variables: { id, input } })
      toast.success('Policy updated successfully')
      setEditingPolicy(null)
      refetch()
    } catch (err: any) {
      toast.error(err.message || 'Failed to update policy')
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this policy?')) return

    try {
      await deletePolicy({ variables: { id } })
      toast.success('Policy deleted successfully')
      refetch()
    } catch (err: any) {
      toast.error(err.message || 'Failed to delete policy')
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100">
            Policies
          </h1>
          <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
            Manage traffic routing policies
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="btn btn-primary flex items-center"
        >
          <PlusIcon className="w-5 h-5 mr-2" />
          Add Policy
        </button>
      </div>

      <div className="card">
        {loading ? (
          <div className="flex justify-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500" />
          </div>
        ) : policies.length === 0 ? (
          <div className="text-center py-12">
            <p className="text-gray-500 dark:text-gray-400 mb-4">
              No policies configured yet
            </p>
            <button
              onClick={() => setShowCreateModal(true)}
              className="btn btn-primary"
            >
              Create your first policy
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead>
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Name
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Priority
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Action
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Packets Matched
                  </th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {policies.map((policy) => (
                  <tr key={policy.id}>
                    <td className="px-6 py-4">
                      <div>
                        <div className="text-sm font-medium text-gray-900 dark:text-gray-100">
                          {policy.name}
                        </div>
                        {policy.description && (
                          <div className="text-sm text-gray-500 dark:text-gray-400">
                            {policy.description}
                          </div>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {policy.priority}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {policy.action}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span
                        className={`badge ${
                          policy.enabled ? 'badge-success' : 'badge-danger'
                        }`}
                      >
                        {policy.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {policy.packetsMatched.toLocaleString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm space-x-2">
                      <button
                        onClick={() => setEditingPolicy(policy)}
                        className="text-blue-600 hover:text-blue-900 dark:text-blue-400 dark:hover:text-blue-300"
                      >
                        <PencilIcon className="w-5 h-5 inline" />
                      </button>
                      <button
                        onClick={() => handleDelete(policy.id)}
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
        <PolicyModal
          onClose={() => setShowCreateModal(false)}
          onSubmit={handleCreate}
        />
      )}

      {editingPolicy && (
        <PolicyModal
          policy={editingPolicy}
          onClose={() => setEditingPolicy(null)}
          onSubmit={(input) => handleUpdate(editingPolicy.id, input)}
        />
      )}
    </div>
  )
}

function PolicyModal({
  policy,
  onClose,
  onSubmit,
}: {
  policy?: Policy
  onClose: () => void
  onSubmit: (input: CreatePolicyInput | UpdatePolicyInput) => void
}) {
  const [name, setName] = useState(policy?.name || '')
  const [description, setDescription] = useState(policy?.description || '')
  const [priority, setPriority] = useState(policy?.priority || 100)
  const [matchRules, setMatchRules] = useState(policy?.matchRules || '{}')
  const [action, setAction] = useState(policy?.action || 'route_lowest_latency')
  const [enabled, setEnabled] = useState(policy?.enabled ?? true)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    const input = {
      name,
      description: description || undefined,
      priority,
      matchRules,
      action,
      enabled,
    }

    onSubmit(input)
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-2xl w-full max-h-[90vh] overflow-y-auto">
        <h2 className="text-xl font-bold text-gray-900 dark:text-gray-100 mb-4">
          {policy ? 'Edit Policy' : 'Create Policy'}
        </h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="name" className="label">
              Name
            </label>
            <input
              id="name"
              type="text"
              required
              className="input"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <div>
            <label htmlFor="description" className="label">
              Description
            </label>
            <textarea
              id="description"
              rows={2}
              className="input"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>
          <div>
            <label htmlFor="priority" className="label">
              Priority (higher = more important)
            </label>
            <input
              id="priority"
              type="number"
              required
              min="0"
              max="1000"
              className="input"
              value={priority}
              onChange={(e) => setPriority(parseInt(e.target.value))}
            />
          </div>
          <div>
            <label htmlFor="matchRules" className="label">
              Match Rules (JSON)
            </label>
            <textarea
              id="matchRules"
              rows={4}
              required
              className="input font-mono text-sm"
              value={matchRules}
              onChange={(e) => setMatchRules(e.target.value)}
              placeholder='{"protocol": "tcp", "dst_port": 443}'
            />
          </div>
          <div>
            <label htmlFor="action" className="label">
              Action
            </label>
            <select
              id="action"
              className="input"
              value={action}
              onChange={(e) => setAction(e.target.value)}
            >
              <option value="route_lowest_latency">Route - Lowest Latency</option>
              <option value="route_highest_bandwidth">Route - Highest Bandwidth</option>
              <option value="route_least_loss">Route - Least Packet Loss</option>
              <option value="route_round_robin">Route - Round Robin</option>
              <option value="drop">Drop</option>
              <option value="allow">Allow</option>
            </select>
          </div>
          <div className="flex items-center">
            <input
              id="enabled"
              type="checkbox"
              className="w-4 h-4 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            <label
              htmlFor="enabled"
              className="ml-2 text-sm font-medium text-gray-900 dark:text-gray-100"
            >
              Enabled
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
              {policy ? 'Update' : 'Create'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
