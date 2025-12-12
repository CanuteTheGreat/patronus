import { useState, useMemo } from 'react'
import { useQuery, useMutation } from '@apollo/client'
import {
  GET_SITES,
  GET_PATHS,
  CREATE_SITE,
  UPDATE_SITE,
  DELETE_SITE,
} from '../graphql/queries'
import type { Site, Path, CreateSiteInput, UpdateSiteInput } from '../types'
import { getQualityColor, getStatusColor } from '../types'
import toast from 'react-hot-toast'
import {
  PlusIcon,
  PencilIcon,
  TrashIcon,
  EyeIcon,
  FunnelIcon,
  XMarkIcon,
  MapPinIcon,
  SignalIcon,
  ClockIcon,
} from '@heroicons/react/24/outline'
import dayjs from 'dayjs'
import Loading from '../components/Loading'
import SearchInput from '../components/SearchInput'
import Pagination from '../components/Pagination'
import ConfirmModal from '../components/ConfirmModal'
import EmptyState from '../components/EmptyState'
import StatusBadge from '../components/StatusBadge'

export default function Sites() {
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [editingSite, setEditingSite] = useState<Site | null>(null)
  const [viewingSite, setViewingSite] = useState<Site | null>(null)
  const [deletingSite, setDeletingSite] = useState<Site | null>(null)
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('')
  const [page, setPage] = useState(1)
  const [itemsPerPage, setItemsPerPage] = useState(10)

  const { data, loading, refetch } = useQuery(GET_SITES)
  const { data: pathsData } = useQuery(GET_PATHS)
  const [createSite, { loading: creating }] = useMutation(CREATE_SITE)
  const [updateSite, { loading: updating }] = useMutation(UPDATE_SITE)
  const [deleteSite, { loading: deleting }] = useMutation(DELETE_SITE)

  const sites: Site[] = data?.sites || []
  const paths: Path[] = pathsData?.paths || []

  // Filter and search sites
  const filteredSites = useMemo(() => {
    return sites.filter((site) => {
      const matchesSearch =
        !search ||
        site.name.toLowerCase().includes(search.toLowerCase()) ||
        site.location.toLowerCase().includes(search.toLowerCase())
      const matchesStatus = !statusFilter || site.status === statusFilter
      return matchesSearch && matchesStatus
    })
  }, [sites, search, statusFilter])

  // Pagination
  const totalPages = Math.ceil(filteredSites.length / itemsPerPage)
  const paginatedSites = filteredSites.slice(
    (page - 1) * itemsPerPage,
    page * itemsPerPage
  )

  // Get paths for a site
  const getSitePaths = (siteId: string) => {
    return paths.filter(
      (p) => p.sourceSiteId === siteId || p.destinationSiteId === siteId
    )
  }

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

  const handleDelete = async () => {
    if (!deletingSite) return

    try {
      await deleteSite({ variables: { id: deletingSite.id } })
      toast.success('Site deleted successfully')
      setDeletingSite(null)
      refetch()
    } catch (err: any) {
      toast.error(err.message || 'Failed to delete site')
    }
  }

  const clearFilters = () => {
    setSearch('')
    setStatusFilter('')
    setPage(1)
  }

  const hasFilters = search || statusFilter

  if (loading) {
    return <Loading message="Loading sites..." />
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100">
            Sites
          </h1>
          <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
            Manage your SD-WAN sites ({filteredSites.length} of {sites.length})
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="mt-4 md:mt-0 btn btn-primary flex items-center"
        >
          <PlusIcon className="w-5 h-5 mr-2" />
          Add Site
        </button>
      </div>

      {/* Filters */}
      <div className="card">
        <div className="flex flex-col md:flex-row md:items-center gap-4">
          <SearchInput
            value={search}
            onChange={setSearch}
            placeholder="Search sites..."
            className="flex-1"
          />
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <FunnelIcon className="w-5 h-5 text-gray-400" />
              <select
                value={statusFilter}
                onChange={(e) => {
                  setStatusFilter(e.target.value)
                  setPage(1)
                }}
                className="input w-40"
                aria-label="Filter by status"
              >
                <option value="">All Status</option>
                <option value="Active">Active</option>
                <option value="Degraded">Degraded</option>
                <option value="Down">Down</option>
              </select>
            </div>
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

      {/* Sites Table */}
      <div className="card">
        {paginatedSites.length === 0 ? (
          <EmptyState
            title={hasFilters ? 'No sites match your filters' : 'No sites configured yet'}
            description={
              hasFilters
                ? 'Try adjusting your search or filters'
                : 'Create your first site to get started with your SD-WAN network'
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
                  Create your first site
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
                      Paths
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
                  {paginatedSites.map((site) => {
                    const sitePaths = getSitePaths(site.id)
                    const activePaths = sitePaths.filter(p => p.status === 'Active').length
                    return (
                      <tr key={site.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center">
                            <div className={`w-2 h-2 rounded-full mr-3 ${site.status === 'Active' ? 'bg-green-500' : site.status === 'Degraded' ? 'bg-yellow-500' : 'bg-red-500'}`} />
                            <span className="text-sm font-medium text-gray-900 dark:text-gray-100">
                              {site.name}
                            </span>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                          <div className="flex items-center">
                            <MapPinIcon className="w-4 h-4 mr-1" />
                            {site.location}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <StatusBadge status={site.status} />
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                          {site.endpointCount}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                          <span className="text-green-600 dark:text-green-400">{activePaths}</span>
                          <span className="text-gray-400"> / {sitePaths.length}</span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                          {dayjs(site.updatedAt).format('MMM D, YYYY HH:mm')}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-right text-sm space-x-2">
                          <button
                            onClick={() => setViewingSite(site)}
                            className="text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-200"
                            title="View details"
                          >
                            <EyeIcon className="w-5 h-5 inline" />
                          </button>
                          <button
                            onClick={() => setEditingSite(site)}
                            className="text-blue-600 hover:text-blue-900 dark:text-blue-400 dark:hover:text-blue-300"
                            title="Edit site"
                          >
                            <PencilIcon className="w-5 h-5 inline" />
                          </button>
                          <button
                            onClick={() => setDeletingSite(site)}
                            className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300"
                            title="Delete site"
                          >
                            <TrashIcon className="w-5 h-5 inline" />
                          </button>
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
                totalItems={filteredSites.length}
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
        <SiteModal
          onClose={() => setShowCreateModal(false)}
          onSubmit={handleCreate}
          loading={creating}
        />
      )}

      {/* Edit Modal */}
      {editingSite && (
        <SiteModal
          site={editingSite}
          onClose={() => setEditingSite(null)}
          onSubmit={(input) => handleUpdate(editingSite.id, input)}
          loading={updating}
        />
      )}

      {/* View Modal */}
      {viewingSite && (
        <SiteDetailModal
          site={viewingSite}
          paths={getSitePaths(viewingSite.id)}
          sites={sites}
          onClose={() => setViewingSite(null)}
          onEdit={() => {
            setEditingSite(viewingSite)
            setViewingSite(null)
          }}
        />
      )}

      {/* Delete Confirmation */}
      <ConfirmModal
        isOpen={!!deletingSite}
        onClose={() => setDeletingSite(null)}
        onConfirm={handleDelete}
        title="Delete Site"
        message={`Are you sure you want to delete "${deletingSite?.name}"? This will also delete all associated paths and configurations. This action cannot be undone.`}
        confirmText="Delete"
        variant="danger"
        loading={deleting}
      />
    </div>
  )
}

function SiteModal({
  site,
  onClose,
  onSubmit,
  loading,
}: {
  site?: Site
  onClose: () => void
  onSubmit: (input: CreateSiteInput | UpdateSiteInput) => void
  loading?: boolean
}) {
  const [name, setName] = useState(site?.name || '')
  const [location, setLocation] = useState(site?.location || '')
  const [status, setStatus] = useState(site?.status || 'Active')

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSubmit(site ? { name, location, status } : { name, location })
  }

  return (
    <div
      className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="site-modal-title"
    >
      <div
        className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4"
        onClick={(e) => e.stopPropagation()}
      >
        <h2
          id="site-modal-title"
          className="text-xl font-bold text-gray-900 dark:text-gray-100 mb-4"
        >
          {site ? 'Edit Site' : 'Create Site'}
        </h2>
        <form onSubmit={handleSubmit} className="space-y-4">
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
              placeholder="e.g., Headquarters"
            />
          </div>
          <div>
            <label htmlFor="location" className="label">
              Location <span className="text-red-500">*</span>
            </label>
            <input
              id="location"
              type="text"
              required
              className="input"
              value={location}
              onChange={(e) => setLocation(e.target.value)}
              placeholder="e.g., New York, USA"
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
                onChange={(e) => setStatus(e.target.value as Site['status'])}
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
              disabled={loading}
              className="btn btn-secondary"
            >
              Cancel
            </button>
            <button type="submit" disabled={loading} className="btn btn-primary">
              {loading ? 'Saving...' : site ? 'Update' : 'Create'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function SiteDetailModal({
  site,
  paths,
  sites,
  onClose,
  onEdit,
}: {
  site: Site
  paths: Path[]
  sites: Site[]
  onClose: () => void
  onEdit: () => void
}) {
  const avgQuality = paths.length > 0
    ? paths.reduce((acc, p) => acc + p.qualityScore, 0) / paths.length
    : 0

  const getSiteName = (id: string) => {
    const s = sites.find(site => site.id === id)
    return s?.name || 'Unknown'
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
              {site.name}
            </h2>
            <div className="flex items-center mt-1 text-gray-500 dark:text-gray-400">
              <MapPinIcon className="w-4 h-4 mr-1" />
              {site.location}
            </div>
          </div>
          <StatusBadge status={site.status} />
        </div>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-4 mb-6">
          <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4 text-center">
            <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
              {site.endpointCount}
            </p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Endpoints</p>
          </div>
          <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4 text-center">
            <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
              {paths.length}
            </p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Paths</p>
          </div>
          <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4 text-center">
            <p className={`text-2xl font-bold ${getQualityColor(avgQuality)}`}>
              {avgQuality.toFixed(1)}%
            </p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Avg Quality</p>
          </div>
        </div>

        {/* Paths */}
        <div className="mb-6">
          <h3 className="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-3 flex items-center">
            <SignalIcon className="w-4 h-4 mr-2" />
            Connected Paths ({paths.length})
          </h3>
          {paths.length > 0 ? (
            <div className="space-y-2">
              {paths.map((path) => {
                const otherSiteId = path.sourceSiteId === site.id
                  ? path.destinationSiteId
                  : path.sourceSiteId
                const direction = path.sourceSiteId === site.id ? 'to' : 'from'
                return (
                  <div
                    key={path.id}
                    className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
                  >
                    <div>
                      <span className="text-sm text-gray-500 dark:text-gray-400">{direction} </span>
                      <span className="text-sm font-medium text-gray-900 dark:text-gray-100">
                        {getSiteName(otherSiteId)}
                      </span>
                    </div>
                    <div className="flex items-center space-x-4 text-sm">
                      <span className="text-gray-500 dark:text-gray-400">
                        {path.latencyMs.toFixed(1)}ms
                      </span>
                      <span className={`font-medium ${getQualityColor(path.qualityScore)}`}>
                        {path.qualityScore.toFixed(0)}%
                      </span>
                      <StatusBadge status={path.status} size="sm" />
                    </div>
                  </div>
                )
              })}
            </div>
          ) : (
            <p className="text-sm text-gray-500 dark:text-gray-400">
              No paths connected to this site.
            </p>
          )}
        </div>

        {/* Timestamps */}
        <div className="flex items-center text-sm text-gray-500 dark:text-gray-400 mb-6">
          <ClockIcon className="w-4 h-4 mr-1" />
          Created {dayjs(site.createdAt).format('MMM D, YYYY')} | Updated{' '}
          {dayjs(site.updatedAt).format('MMM D, YYYY HH:mm')}
        </div>

        {/* Actions */}
        <div className="flex justify-end space-x-3">
          <button onClick={onClose} className="btn btn-secondary">
            Close
          </button>
          <button onClick={onEdit} className="btn btn-primary">
            Edit Site
          </button>
        </div>
      </div>
    </div>
  )
}
