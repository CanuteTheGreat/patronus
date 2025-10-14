import { useState } from 'react'
import { useQuery, useMutation } from '@apollo/client'
import {
  GET_SITES,
  CREATE_SITE,
  UPDATE_SITE,
  DELETE_SITE,
} from '../graphql/queries'
import type { Site, CreateSiteInput, UpdateSiteInput } from '../types'
import toast from 'react-hot-toast'
import { PlusIcon, PencilIcon, TrashIcon } from '@heroicons/react/24/outline'
import dayjs from 'dayjs'

export default function Sites() {
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [editingSite, setEditingSite] = useState<Site | null>(null)

  const { data, loading, refetch } = useQuery(GET_SITES)
  const [createSite] = useMutation(CREATE_SITE)
  const [updateSite] = useMutation(UPDATE_SITE)
  const [deleteSite] = useMutation(DELETE_SITE)

  const sites: Site[] = data?.sites || []

  const handleCreate = async (input: CreateSiteInput) => {
    try {
      await createSite({ variables: { input } })
      toast.success('Site created successfully')
      setShowCreateModal(false)
      refetch()
    } catch (err: any) {
      toast.error(err.message || 'Failed to create site')
    }
  }

  const handleUpdate = async (id: string, input: UpdateSiteInput) => {
    try {
      await updateSite({ variables: { id, input } })
      toast.success('Site updated successfully')
      setEditingSite(null)
      refetch()
    } catch (err: any) {
      toast.error(err.message || 'Failed to update site')
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this site?')) return

    try {
      await deleteSite({ variables: { id } })
      toast.success('Site deleted successfully')
      refetch()
    } catch (err: any) {
      toast.error(err.message || 'Failed to delete site')
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100">
            Sites
          </h1>
          <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
            Manage your SD-WAN sites
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="btn btn-primary flex items-center"
        >
          <PlusIcon className="w-5 h-5 mr-2" />
          Add Site
        </button>
      </div>

      <div className="card">
        {loading ? (
          <div className="flex justify-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500" />
          </div>
        ) : sites.length === 0 ? (
          <div className="text-center py-12">
            <p className="text-gray-500 dark:text-gray-400 mb-4">
              No sites configured yet
            </p>
            <button
              onClick={() => setShowCreateModal(true)}
              className="btn btn-primary"
            >
              Create your first site
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
                    Location
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Endpoints
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Updated
                  </th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {sites.map((site) => (
                  <tr key={site.id}>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-gray-100">
                      {site.name}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {site.location}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <StatusBadge status={site.status} />
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {site.endpointCount}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {dayjs(site.updatedAt).format('MMM D, YYYY HH:mm')}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm space-x-2">
                      <button
                        onClick={() => setEditingSite(site)}
                        className="text-blue-600 hover:text-blue-900 dark:text-blue-400 dark:hover:text-blue-300"
                      >
                        <PencilIcon className="w-5 h-5 inline" />
                      </button>
                      <button
                        onClick={() => handleDelete(site.id)}
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
        <SiteModal
          onClose={() => setShowCreateModal(false)}
          onSubmit={handleCreate}
        />
      )}

      {editingSite && (
        <SiteModal
          site={editingSite}
          onClose={() => setEditingSite(null)}
          onSubmit={(input) => handleUpdate(editingSite.id, input)}
        />
      )}
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
  const statusClasses = {
    Active: 'badge-success',
    Degraded: 'badge-warning',
    Down: 'badge-danger',
  }

  return (
    <span className={`badge ${statusClasses[status as keyof typeof statusClasses]}`}>
      {status}
    </span>
  )
}

function SiteModal({
  site,
  onClose,
  onSubmit,
}: {
  site?: Site
  onClose: () => void
  onSubmit: (input: CreateSiteInput | UpdateSiteInput) => void
}) {
  const [name, setName] = useState(site?.name || '')
  const [location, setLocation] = useState(site?.location || '')
  const [status, setStatus] = useState(site?.status || 'Active')

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSubmit(site ? { name, location, status } : { name, location })
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md w-full">
        <h2 className="text-xl font-bold text-gray-900 dark:text-gray-100 mb-4">
          {site ? 'Edit Site' : 'Create Site'}
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
            <label htmlFor="location" className="label">
              Location
            </label>
            <input
              id="location"
              type="text"
              required
              className="input"
              value={location}
              onChange={(e) => setLocation(e.target.value)}
            />
          </div>
          {site && (
            <div>
              <label htmlFor="status" className="label">
                Status
              </label>
              <select
                id="status"
                className="input"
                value={status}
                onChange={(e) => setStatus(e.target.value)}
              >
                <option value="Active">Active</option>
                <option value="Degraded">Degraded</option>
                <option value="Down">Down</option>
              </select>
            </div>
          )}
          <div className="flex justify-end space-x-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="btn btn-secondary"
            >
              Cancel
            </button>
            <button type="submit" className="btn btn-primary">
              {site ? 'Update' : 'Create'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
