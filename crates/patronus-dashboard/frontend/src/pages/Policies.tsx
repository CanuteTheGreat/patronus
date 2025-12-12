import { useState, useMemo } from 'react'
import { useQuery, useMutation } from '@apollo/client'
import {
  GET_POLICIES,
  CREATE_POLICY,
  UPDATE_POLICY,
  DELETE_POLICY,
  TOGGLE_POLICY,
} from '../graphql/queries'
import type { Policy, CreatePolicyInput, UpdatePolicyInput } from '../types'
import { POLICY_ACTIONS, formatBytes, formatNumber } from '../types'
import toast from 'react-hot-toast'
import {
  PlusIcon,
  PencilIcon,
  TrashIcon,
  EyeIcon,
  FunnelIcon,
  XMarkIcon,
  PlayIcon,
  PauseIcon,
  DocumentDuplicateIcon,
  ArrowsUpDownIcon,
  CheckCircleIcon,
  ExclamationCircleIcon,
} from '@heroicons/react/24/outline'
import dayjs from 'dayjs'
import Loading from '../components/Loading'
import SearchInput from '../components/SearchInput'
import Pagination from '../components/Pagination'
import ConfirmModal from '../components/ConfirmModal'
import EmptyState from '../components/EmptyState'

export default function Policies() {
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [editingPolicy, setEditingPolicy] = useState<Policy | null>(null)
  const [viewingPolicy, setViewingPolicy] = useState<Policy | null>(null)
  const [deletingPolicy, setDeletingPolicy] = useState<Policy | null>(null)
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('')
  const [actionFilter, setActionFilter] = useState<string>('')
  const [page, setPage] = useState(1)
  const [itemsPerPage, setItemsPerPage] = useState(10)

  const { data, loading, refetch } = useQuery(GET_POLICIES)
  const [createPolicy, { loading: creating }] = useMutation(CREATE_POLICY)
  const [updatePolicy, { loading: updating }] = useMutation(UPDATE_POLICY)
  const [deletePolicy, { loading: deleting }] = useMutation(DELETE_POLICY)
  const [togglePolicy] = useMutation(TOGGLE_POLICY)

  const policies: Policy[] = data?.policies || []

  // Filter and search policies
  const filteredPolicies = useMemo(() => {
    return policies
      .filter((policy) => {
        const matchesSearch =
          !search ||
          policy.name.toLowerCase().includes(search.toLowerCase()) ||
          policy.description?.toLowerCase().includes(search.toLowerCase())
        const matchesStatus =
          !statusFilter ||
          (statusFilter === 'enabled' && policy.enabled) ||
          (statusFilter === 'disabled' && !policy.enabled)
        const matchesAction = !actionFilter || policy.action === actionFilter
        return matchesSearch && matchesStatus && matchesAction
      })
      .sort((a, b) => b.priority - a.priority) // Sort by priority descending
  }, [policies, search, statusFilter, actionFilter])

  // Pagination
  const totalPages = Math.ceil(filteredPolicies.length / itemsPerPage)
  const paginatedPolicies = filteredPolicies.slice(
    (page - 1) * itemsPerPage,
    page * itemsPerPage
  )

  // Stats
  const totalPackets = policies.reduce((acc, p) => acc + p.packetsMatched, 0)
  const totalBytes = policies.reduce((acc, p) => acc + p.bytesMatched, 0)
  const enabledCount = policies.filter((p) => p.enabled).length

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

  const handleDelete = async () => {
    if (!deletingPolicy) return

    try {
      await deletePolicy({ variables: { id: deletingPolicy.id } })
      toast.success('Policy deleted successfully')
      setDeletingPolicy(null)
      refetch()
    } catch (err: any) {
      toast.error(err.message || 'Failed to delete policy')
    }
  }

  const handleToggle = async (policy: Policy) => {
    try {
      await togglePolicy({ variables: { id: policy.id, enabled: !policy.enabled } })
      toast.success(`Policy ${policy.enabled ? 'disabled' : 'enabled'}`)
      refetch()
    } catch (err: any) {
      toast.error(err.message || 'Failed to toggle policy')
    }
  }

  const handleDuplicate = (policy: Policy) => {
    setShowCreateModal(true)
    // Pre-fill with copied policy data (handled in modal)
  }

  const clearFilters = () => {
    setSearch('')
    setStatusFilter('')
    setActionFilter('')
    setPage(1)
  }

  const hasFilters = search || statusFilter || actionFilter

  if (loading) {
    return <Loading message="Loading policies..." />
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100">
            Policies
          </h1>
          <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
            Manage traffic routing policies ({filteredPolicies.length} of {policies.length})
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="mt-4 md:mt-0 btn btn-primary flex items-center"
        >
          <PlusIcon className="w-5 h-5 mr-2" />
          Add Policy
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="card">
          <p className="text-sm text-gray-500 dark:text-gray-400">Total Policies</p>
          <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">{policies.length}</p>
        </div>
        <div className="card">
          <p className="text-sm text-gray-500 dark:text-gray-400">Enabled</p>
          <p className="text-2xl font-bold text-green-600 dark:text-green-400">{enabledCount}</p>
        </div>
        <div className="card">
          <p className="text-sm text-gray-500 dark:text-gray-400">Packets Matched</p>
          <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">{formatNumber(totalPackets)}</p>
        </div>
        <div className="card">
          <p className="text-sm text-gray-500 dark:text-gray-400">Data Matched</p>
          <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">{formatBytes(totalBytes)}</p>
        </div>
      </div>

      {/* Filters */}
      <div className="card">
        <div className="flex flex-col md:flex-row md:items-center gap-4">
          <SearchInput
            value={search}
            onChange={setSearch}
            placeholder="Search policies..."
            className="flex-1"
          />
          <div className="flex items-center gap-4 flex-wrap">
            <div className="flex items-center gap-2">
              <FunnelIcon className="w-5 h-5 text-gray-400" />
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
                <option value="enabled">Enabled</option>
                <option value="disabled">Disabled</option>
              </select>
            </div>
            <select
              value={actionFilter}
              onChange={(e) => {
                setActionFilter(e.target.value)
                setPage(1)
              }}
              className="input w-48"
              aria-label="Filter by action"
            >
              <option value="">All Actions</option>
              {POLICY_ACTIONS.map((action) => (
                <option key={action.value} value={action.value}>
                  {action.label}
                </option>
              ))}
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

      {/* Policies Table */}
      <div className="card">
        {paginatedPolicies.length === 0 ? (
          <EmptyState
            title={hasFilters ? 'No policies match your filters' : 'No policies configured yet'}
            description={
              hasFilters
                ? 'Try adjusting your search or filters'
                : 'Create your first policy to start routing traffic'
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
                  Create your first policy
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
                      <div className="flex items-center">
                        Priority
                        <ArrowsUpDownIcon className="w-4 h-4 ml-1" />
                      </div>
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Name
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Action
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Packets
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Data
                    </th>
                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                  {paginatedPolicies.map((policy) => (
                    <tr key={policy.id} className={`hover:bg-gray-50 dark:hover:bg-gray-700/50 ${!policy.enabled ? 'opacity-60' : ''}`}>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="inline-flex items-center justify-center w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 font-semibold text-sm">
                          {policy.priority}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <div>
                          <div className="text-sm font-medium text-gray-900 dark:text-gray-100">
                            {policy.name}
                          </div>
                          {policy.description && (
                            <div className="text-sm text-gray-500 dark:text-gray-400 truncate max-w-xs">
                              {policy.description}
                            </div>
                          )}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="text-sm text-gray-900 dark:text-gray-100">
                          {getActionLabel(policy.action)}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <button
                          onClick={() => handleToggle(policy)}
                          className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium transition-colors ${
                            policy.enabled
                              ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200 hover:bg-green-200 dark:hover:bg-green-800'
                              : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
                          }`}
                          title={policy.enabled ? 'Click to disable' : 'Click to enable'}
                        >
                          {policy.enabled ? (
                            <>
                              <CheckCircleIcon className="w-4 h-4 mr-1" />
                              Enabled
                            </>
                          ) : (
                            <>
                              <PauseIcon className="w-4 h-4 mr-1" />
                              Disabled
                            </>
                          )}
                        </button>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                        {formatNumber(policy.packetsMatched)}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                        {formatBytes(policy.bytesMatched)}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-right text-sm space-x-2">
                        <button
                          onClick={() => setViewingPolicy(policy)}
                          className="text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-200"
                          title="View details"
                        >
                          <EyeIcon className="w-5 h-5 inline" />
                        </button>
                        <button
                          onClick={() => setEditingPolicy(policy)}
                          className="text-blue-600 hover:text-blue-900 dark:text-blue-400 dark:hover:text-blue-300"
                          title="Edit policy"
                        >
                          <PencilIcon className="w-5 h-5 inline" />
                        </button>
                        <button
                          onClick={() => setDeletingPolicy(policy)}
                          className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300"
                          title="Delete policy"
                        >
                          <TrashIcon className="w-5 h-5 inline" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
              <Pagination
                currentPage={page}
                totalPages={totalPages}
                totalItems={filteredPolicies.length}
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
        <PolicyModal
          onClose={() => setShowCreateModal(false)}
          onSubmit={handleCreate}
          loading={creating}
        />
      )}

      {/* Edit Modal */}
      {editingPolicy && (
        <PolicyModal
          policy={editingPolicy}
          onClose={() => setEditingPolicy(null)}
          onSubmit={(input) => handleUpdate(editingPolicy.id, input)}
          loading={updating}
        />
      )}

      {/* View Modal */}
      {viewingPolicy && (
        <PolicyDetailModal
          policy={viewingPolicy}
          onClose={() => setViewingPolicy(null)}
          onEdit={() => {
            setEditingPolicy(viewingPolicy)
            setViewingPolicy(null)
          }}
        />
      )}

      {/* Delete Confirmation */}
      <ConfirmModal
        isOpen={!!deletingPolicy}
        onClose={() => setDeletingPolicy(null)}
        onConfirm={handleDelete}
        title="Delete Policy"
        message={`Are you sure you want to delete "${deletingPolicy?.name}"? This action cannot be undone.`}
        confirmText="Delete"
        variant="danger"
        loading={deleting}
      />
    </div>
  )
}

function getActionLabel(action: string): string {
  const found = POLICY_ACTIONS.find((a) => a.value === action)
  return found?.label || action
}

function PolicyModal({
  policy,
  onClose,
  onSubmit,
  loading,
}: {
  policy?: Policy
  onClose: () => void
  onSubmit: (input: CreatePolicyInput | UpdatePolicyInput) => void
  loading?: boolean
}) {
  const [name, setName] = useState(policy?.name || '')
  const [description, setDescription] = useState(policy?.description || '')
  const [priority, setPriority] = useState(policy?.priority || 100)
  const [matchRules, setMatchRules] = useState(policy?.matchRules || '{\n  \n}')
  const [action, setAction] = useState(policy?.action || 'route_lowest_latency')
  const [enabled, setEnabled] = useState(policy?.enabled ?? true)
  const [jsonError, setJsonError] = useState<string | null>(null)

  const validateJson = (value: string) => {
    try {
      JSON.parse(value)
      setJsonError(null)
      return true
    } catch (e: any) {
      setJsonError(e.message)
      return false
    }
  }

  const handleMatchRulesChange = (value: string) => {
    setMatchRules(value)
    validateJson(value)
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    if (!validateJson(matchRules)) {
      toast.error('Invalid JSON in match rules')
      return
    }

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

  const formatJson = () => {
    try {
      const parsed = JSON.parse(matchRules)
      setMatchRules(JSON.stringify(parsed, null, 2))
      setJsonError(null)
    } catch (e) {
      // Already invalid
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
        className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="text-xl font-bold text-gray-900 dark:text-gray-100 mb-4">
          {policy ? 'Edit Policy' : 'Create Policy'}
        </h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label htmlFor="name" className="label">
                Name <span className="text-red-500">*</span>
              </label>
              <input
                id="name"
                type="text"
                required
                className="input"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g., Voice Traffic Priority"
              />
            </div>
            <div>
              <label htmlFor="priority" className="label">
                Priority (higher = first)
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
              placeholder="Optional description..."
            />
          </div>

          <div>
            <div className="flex items-center justify-between mb-2">
              <label htmlFor="matchRules" className="label mb-0">
                Match Rules (JSON) <span className="text-red-500">*</span>
              </label>
              <button
                type="button"
                onClick={formatJson}
                className="text-xs text-blue-600 dark:text-blue-400 hover:underline"
              >
                Format JSON
              </button>
            </div>
            <textarea
              id="matchRules"
              rows={8}
              required
              className={`input font-mono text-sm ${jsonError ? 'border-red-500 focus:ring-red-500' : ''}`}
              value={matchRules}
              onChange={(e) => handleMatchRulesChange(e.target.value)}
              placeholder='{"protocol": "tcp", "dst_port": 443}'
            />
            {jsonError ? (
              <p className="mt-1 text-sm text-red-500 flex items-center">
                <ExclamationCircleIcon className="w-4 h-4 mr-1" />
                {jsonError}
              </p>
            ) : (
              <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                Example: {"{"}"protocol": "tcp", "dst_port": 443, "src_ip": "10.0.0.0/8"{"}"}
              </p>
            )}
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
              {POLICY_ACTIONS.map((a) => (
                <option key={a.value} value={a.value}>
                  {a.label}
                </option>
              ))}
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
              disabled={loading}
              className="btn btn-secondary"
            >
              Cancel
            </button>
            <button type="submit" disabled={loading || !!jsonError} className="btn btn-primary">
              {loading ? 'Saving...' : policy ? 'Update' : 'Create'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function PolicyDetailModal({
  policy,
  onClose,
  onEdit,
}: {
  policy: Policy
  onClose: () => void
  onEdit: () => void
}) {
  let parsedRules: object | null = null
  try {
    parsedRules = JSON.parse(policy.matchRules)
  } catch {
    // Invalid JSON
  }

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
          <div>
            <h2 className="text-xl font-bold text-gray-900 dark:text-gray-100">
              {policy.name}
            </h2>
            {policy.description && (
              <p className="mt-1 text-gray-500 dark:text-gray-400">
                {policy.description}
              </p>
            )}
          </div>
          <span
            className={`badge ${policy.enabled ? 'badge-success' : 'badge-danger'}`}
          >
            {policy.enabled ? 'Enabled' : 'Disabled'}
          </span>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-4 gap-4 mb-6">
          <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4 text-center">
            <p className="text-2xl font-bold text-blue-600 dark:text-blue-400">
              {policy.priority}
            </p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Priority</p>
          </div>
          <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4 text-center">
            <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
              {formatNumber(policy.packetsMatched)}
            </p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Packets</p>
          </div>
          <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4 text-center">
            <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
              {formatBytes(policy.bytesMatched)}
            </p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Data</p>
          </div>
          <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4 text-center">
            <p className="text-lg font-bold text-gray-900 dark:text-gray-100 truncate">
              {getActionLabel(policy.action).split(' - ')[0]}
            </p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Action</p>
          </div>
        </div>

        {/* Match Rules */}
        <div className="mb-6">
          <h3 className="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-3">
            Match Rules
          </h3>
          <pre className="bg-gray-100 dark:bg-gray-700 rounded-lg p-4 text-sm overflow-x-auto">
            {parsedRules
              ? JSON.stringify(parsedRules, null, 2)
              : policy.matchRules}
          </pre>
        </div>

        {/* Created Date */}
        <p className="text-sm text-gray-500 dark:text-gray-400 mb-6">
          Created {dayjs(policy.createdAt).format('MMMM D, YYYY [at] HH:mm')}
        </p>

        {/* Actions */}
        <div className="flex justify-end space-x-3">
          <button onClick={onClose} className="btn btn-secondary">
            Close
          </button>
          <button onClick={onEdit} className="btn btn-primary">
            Edit Policy
          </button>
        </div>
      </div>
    </div>
  )
}
