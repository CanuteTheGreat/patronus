import { useState } from 'react'
import { useQuery } from '@apollo/client'
import { GET_SITES, GET_PATHS } from '../graphql/queries'
import type { Site, Path } from '../types'
import { getQualityColor } from '../types'
import {
  XMarkIcon,
  MapPinIcon,
  SignalIcon,
  ArrowPathIcon,
  ArrowsRightLeftIcon,
  ClockIcon,
  ExclamationTriangleIcon,
} from '@heroicons/react/24/outline'
import dayjs from 'dayjs'
import relativeTime from 'dayjs/plugin/relativeTime'
import Loading from '../components/Loading'
import StatusBadge, { QualityBadge } from '../components/StatusBadge'
import NetworkTopology from '../components/NetworkTopology'

dayjs.extend(relativeTime)

export default function Topology() {
  const [selectedSite, setSelectedSite] = useState<Site | null>(null)
  const [selectedPath, setSelectedPath] = useState<Path | null>(null)

  const { data: sitesData, loading: sitesLoading, refetch } = useQuery(GET_SITES)
  const { data: pathsData, loading: pathsLoading } = useQuery(GET_PATHS)

  const sites: Site[] = sitesData?.sites || []
  const paths: Path[] = pathsData?.paths || []

  // Stats
  const activeSites = sites.filter((s) => s.status === 'Active').length
  const degradedSites = sites.filter((s) => s.status === 'Degraded').length
  const downSites = sites.filter((s) => s.status === 'Down').length

  const activePaths = paths.filter((p) => p.status === 'Active').length
  const avgQuality = paths.length > 0
    ? paths.reduce((acc, p) => acc + p.qualityScore, 0) / paths.length
    : 0

  const getSitePaths = (siteId: string) => {
    return paths.filter(
      (p) => p.sourceSiteId === siteId || p.destinationSiteId === siteId
    )
  }

  const getSiteName = (id: string) => {
    const site = sites.find((s) => s.id === id)
    return site?.name || 'Unknown'
  }

  const isLoading = sitesLoading || pathsLoading

  if (isLoading) {
    return <Loading message="Loading network topology..." />
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100">
            Network Topology
          </h1>
          <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
            Visual representation of your SD-WAN network
          </p>
        </div>
        <button
          onClick={() => refetch()}
          className="mt-4 md:mt-0 btn btn-secondary flex items-center"
        >
          <ArrowPathIcon className="w-5 h-5 mr-2" />
          Refresh
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <StatCard title="Sites" value={sites.length} />
        <StatCard title="Active" value={activeSites} color="green" />
        <StatCard title="Degraded" value={degradedSites} color="yellow" />
        <StatCard title="Down" value={downSites} color="red" />
        <StatCard
          title="Avg Quality"
          value={`${avgQuality.toFixed(1)}%`}
          color={avgQuality >= 80 ? 'green' : avgQuality >= 50 ? 'yellow' : 'red'}
        />
      </div>

      {/* Alerts */}
      {downSites > 0 && (
        <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 rounded-lg p-4">
          <div className="flex items-center">
            <ExclamationTriangleIcon className="w-5 h-5 text-red-600 dark:text-red-400 mr-2" />
            <span className="text-red-800 dark:text-red-200 font-medium">
              {downSites} site{downSites > 1 ? 's' : ''} currently down
            </span>
          </div>
        </div>
      )}

      {/* Main Content */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Topology Visualization */}
        <div className="lg:col-span-2 card">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
            Network Map
          </h3>
          {sites.length === 0 ? (
            <div className="flex items-center justify-center h-[500px] text-gray-500 dark:text-gray-400">
              No sites configured. Create sites to view the network topology.
            </div>
          ) : (
            <div className="relative">
              <NetworkTopology height={500} />
              <div className="absolute bottom-4 left-4 bg-white dark:bg-gray-800 rounded-lg p-3 shadow-md">
                <div className="text-xs text-gray-500 dark:text-gray-400 mb-2">Legend</div>
                <div className="space-y-1">
                  <div className="flex items-center">
                    <div className="w-3 h-3 rounded-full bg-green-500 mr-2" />
                    <span className="text-xs text-gray-700 dark:text-gray-300">Active</span>
                  </div>
                  <div className="flex items-center">
                    <div className="w-3 h-3 rounded-full bg-yellow-500 mr-2" />
                    <span className="text-xs text-gray-700 dark:text-gray-300">Degraded</span>
                  </div>
                  <div className="flex items-center">
                    <div className="w-3 h-3 rounded-full bg-red-500 mr-2" />
                    <span className="text-xs text-gray-700 dark:text-gray-300">Down</span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Details Panel */}
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
            Details
          </h3>

          {!selectedSite && !selectedPath && (
            <div className="text-center py-8 text-gray-500 dark:text-gray-400">
              <SignalIcon className="w-12 h-12 mx-auto mb-3 opacity-50" />
              <p>Click on a site or path in the table below to view details</p>
            </div>
          )}

          {selectedSite && (
            <SiteDetailPanel
              site={selectedSite}
              paths={getSitePaths(selectedSite.id)}
              sites={sites}
              onClose={() => setSelectedSite(null)}
            />
          )}

          {selectedPath && (
            <PathDetailPanel
              path={selectedPath}
              sourceSiteName={getSiteName(selectedPath.sourceSiteId)}
              destSiteName={getSiteName(selectedPath.destinationSiteId)}
              onClose={() => setSelectedPath(null)}
            />
          )}
        </div>
      </div>

      {/* Sites List */}
      <div className="card">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
          Sites ({sites.length})
        </h3>
        {sites.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {sites.map((site) => {
              const sitePaths = getSitePaths(site.id)
              const avgQuality = sitePaths.length > 0
                ? sitePaths.reduce((acc, p) => acc + p.qualityScore, 0) / sitePaths.length
                : 0
              return (
                <div
                  key={site.id}
                  className={`p-4 rounded-lg border cursor-pointer transition-all hover:shadow-md ${
                    selectedSite?.id === site.id
                      ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20'
                      : 'border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700/50'
                  }`}
                  onClick={() => {
                    setSelectedPath(null)
                    setSelectedSite(site)
                  }}
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <h4 className="font-medium text-gray-900 dark:text-gray-100">{site.name}</h4>
                      <div className="flex items-center text-sm text-gray-500 dark:text-gray-400 mt-1">
                        <MapPinIcon className="w-4 h-4 mr-1" />
                        {site.location}
                      </div>
                    </div>
                    <div className={`w-3 h-3 rounded-full ${site.status === 'Active' ? 'bg-green-500' : site.status === 'Degraded' ? 'bg-yellow-500' : 'bg-red-500'}`} />
                  </div>
                  <div className="flex items-center justify-between mt-3 pt-3 border-t border-gray-200 dark:border-gray-600 text-sm">
                    <span className="text-gray-500 dark:text-gray-400">{sitePaths.length} paths</span>
                    <span className={avgQuality > 0 ? getQualityColor(avgQuality) : 'text-gray-400'}>
                      {avgQuality > 0 ? `${avgQuality.toFixed(0)}% avg` : 'No paths'}
                    </span>
                  </div>
                </div>
              )
            })}
          </div>
        ) : (
          <p className="text-center py-8 text-gray-500 dark:text-gray-400">
            No sites configured yet.
          </p>
        )}
      </div>

      {/* Path List */}
      <div className="card">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
          All Paths ({paths.length})
        </h3>
        {paths.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead>
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                    Source
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                    Destination
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                    Status
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                    Latency
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                    Loss
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                    Bandwidth
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                    Quality
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {paths.map((path) => (
                  <tr
                    key={path.id}
                    className={`hover:bg-gray-50 dark:hover:bg-gray-700/50 cursor-pointer ${
                      selectedPath?.id === path.id ? 'bg-blue-50 dark:bg-blue-900/20' : ''
                    }`}
                    onClick={() => {
                      setSelectedSite(null)
                      setSelectedPath(path)
                    }}
                  >
                    <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100">
                      {getSiteName(path.sourceSiteId)}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100">
                      {getSiteName(path.destinationSiteId)}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <StatusBadge status={path.status} size="sm" />
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {path.latencyMs.toFixed(2)} ms
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {path.packetLoss.toFixed(3)}%
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {path.bandwidthMbps.toFixed(1)} Mbps
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className={`font-medium ${getQualityColor(path.qualityScore)}`}>
                        {path.qualityScore.toFixed(1)}%
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-center py-8 text-gray-500 dark:text-gray-400">
            No paths configured. Add multiple sites to create network paths.
          </p>
        )}
      </div>
    </div>
  )
}

function StatCard({
  title,
  value,
  color,
}: {
  title: string
  value: number | string
  color?: 'green' | 'yellow' | 'red'
}) {
  const colorClasses = {
    green: 'text-green-600 dark:text-green-400',
    yellow: 'text-yellow-600 dark:text-yellow-400',
    red: 'text-red-600 dark:text-red-400',
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

function SiteDetailPanel({
  site,
  paths,
  sites,
  onClose,
}: {
  site: Site
  paths: Path[]
  sites: Site[]
  onClose: () => void
}) {
  const avgQuality = paths.length > 0
    ? paths.reduce((acc, p) => acc + p.qualityScore, 0) / paths.length
    : 0

  const getSiteName = (id: string) => {
    const s = sites.find((s) => s.id === id)
    return s?.name || 'Unknown'
  }

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between">
        <div>
          <h4 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
            {site.name}
          </h4>
          <div className="flex items-center mt-1 text-sm text-gray-500 dark:text-gray-400">
            <MapPinIcon className="w-4 h-4 mr-1" />
            {site.location}
          </div>
        </div>
        <button
          onClick={onClose}
          className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
          aria-label="Close"
        >
          <XMarkIcon className="w-5 h-5" />
        </button>
      </div>

      <StatusBadge status={site.status} />

      <div className="grid grid-cols-3 gap-2 text-center">
        <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-3">
          <p className="text-xl font-bold text-gray-900 dark:text-gray-100">{site.endpointCount}</p>
          <p className="text-xs text-gray-500 dark:text-gray-400">Endpoints</p>
        </div>
        <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-3">
          <p className="text-xl font-bold text-gray-900 dark:text-gray-100">{paths.length}</p>
          <p className="text-xs text-gray-500 dark:text-gray-400">Paths</p>
        </div>
        <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-3">
          <p className={`text-xl font-bold ${getQualityColor(avgQuality)}`}>
            {avgQuality.toFixed(0)}%
          </p>
          <p className="text-xs text-gray-500 dark:text-gray-400">Avg Quality</p>
        </div>
      </div>

      {paths.length > 0 && (
        <div>
          <h5 className="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2">
            Connected Paths
          </h5>
          <div className="space-y-2 max-h-60 overflow-y-auto">
            {paths.map((path) => {
              const otherSiteId = path.sourceSiteId === site.id
                ? path.destinationSiteId
                : path.sourceSiteId
              const direction = path.sourceSiteId === site.id ? 'to' : 'from'
              return (
                <div
                  key={path.id}
                  className="flex items-center justify-between p-2 bg-gray-50 dark:bg-gray-700/50 rounded text-sm"
                >
                  <div>
                    <span className="text-gray-500 dark:text-gray-400">{direction} </span>
                    <span className="text-gray-900 dark:text-gray-100">{getSiteName(otherSiteId)}</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="text-gray-500 dark:text-gray-400">{path.latencyMs.toFixed(0)}ms</span>
                    <span className={getQualityColor(path.qualityScore)}>{path.qualityScore.toFixed(0)}%</span>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      <div className="flex items-center text-xs text-gray-500 dark:text-gray-400 pt-2 border-t border-gray-200 dark:border-gray-700">
        <ClockIcon className="w-3 h-3 mr-1" />
        Updated {dayjs(site.updatedAt).fromNow()}
      </div>
    </div>
  )
}

function PathDetailPanel({
  path,
  sourceSiteName,
  destSiteName,
  onClose,
}: {
  path: Path
  sourceSiteName: string
  destSiteName: string
  onClose: () => void
}) {
  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between">
        <div>
          <h4 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
            Path Details
          </h4>
          <div className="flex items-center mt-1 text-sm text-gray-500 dark:text-gray-400">
            <ArrowsRightLeftIcon className="w-4 h-4 mr-1" />
            {sourceSiteName} ↔ {destSiteName}
          </div>
        </div>
        <button
          onClick={onClose}
          className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
          aria-label="Close"
        >
          <XMarkIcon className="w-5 h-5" />
        </button>
      </div>

      <div className="flex items-center space-x-2">
        <StatusBadge status={path.status} />
        <QualityBadge score={path.qualityScore} />
      </div>

      <div className="space-y-3">
        <MetricRow label="Latency" value={`${path.latencyMs.toFixed(2)} ms`} />
        <MetricRow label="Packet Loss" value={`${path.packetLoss.toFixed(3)}%`} />
        <MetricRow label="Bandwidth" value={`${path.bandwidthMbps.toFixed(1)} Mbps`} />
        <MetricRow label="Quality Score" value={`${path.qualityScore.toFixed(1)}%`} color={getQualityColor(path.qualityScore)} />
      </div>

      <div className="flex items-center text-xs text-gray-500 dark:text-gray-400 pt-2 border-t border-gray-200 dark:border-gray-700">
        <ClockIcon className="w-3 h-3 mr-1" />
        Last updated {dayjs(path.lastUpdated).fromNow()}
      </div>
    </div>
  )
}

function MetricRow({
  label,
  value,
  color,
}: {
  label: string
  value: string
  color?: string
}) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-gray-100 dark:border-gray-700">
      <span className="text-sm text-gray-500 dark:text-gray-400">{label}</span>
      <span className={`text-sm font-medium ${color || 'text-gray-900 dark:text-gray-100'}`}>
        {value}
      </span>
    </div>
  )
}
