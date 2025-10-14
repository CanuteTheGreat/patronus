import { useEffect, useRef } from 'react'
import { Network } from 'vis-network/standalone'
import { useQuery, useSubscription } from '@apollo/client'
import { GET_SITES, GET_PATHS, SITE_STATUS_SUBSCRIPTION } from '../graphql/queries'
import type { Site, Path } from '../types'

interface NetworkTopologyProps {
  height?: number
}

export default function NetworkTopology({ height = 600 }: NetworkTopologyProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const networkRef = useRef<Network | null>(null)

  const { data: sitesData, loading: sitesLoading, refetch: refetchSites } = useQuery(GET_SITES)
  const { data: pathsData, loading: pathsLoading, refetch: refetchPaths } = useQuery(GET_PATHS)

  // Subscribe to site status changes
  useSubscription(SITE_STATUS_SUBSCRIPTION, {
    onData: () => {
      refetchSites()
      refetchPaths()
    },
  })

  const sites: Site[] = sitesData?.sites || []
  const paths: Path[] = pathsData?.paths || []

  useEffect(() => {
    if (!containerRef.current || sitesLoading || pathsLoading) return

    // Create nodes from sites
    const nodes = sites.map((site) => ({
      id: site.id,
      label: site.name,
      title: `${site.name}\n${site.location}\nStatus: ${site.status}\nEndpoints: ${site.endpointCount}`,
      color: getNodeColor(site.status),
      size: 30,
      font: {
        size: 14,
        color: '#ffffff',
      },
    }))

    // Create edges from paths
    const edges = paths.map((path) => ({
      id: path.id,
      from: path.sourceSiteId,
      to: path.destinationSiteId,
      title: `Latency: ${path.latencyMs.toFixed(2)}ms\nLoss: ${path.packetLoss.toFixed(2)}%\nBandwidth: ${path.bandwidthMbps.toFixed(2)} Mbps\nQuality: ${path.qualityScore.toFixed(1)}`,
      color: getEdgeColor(path.status, path.qualityScore),
      width: 2,
      arrows: {
        to: {
          enabled: true,
          scaleFactor: 0.5,
        },
      },
      smooth: {
        type: 'continuous',
      },
    }))

    const data = { nodes, edges }

    const options = {
      nodes: {
        shape: 'dot',
        borderWidth: 2,
        borderWidthSelected: 4,
      },
      edges: {
        smooth: {
          type: 'continuous',
        },
        font: {
          size: 12,
          align: 'middle',
        },
      },
      physics: {
        enabled: true,
        solver: 'forceAtlas2Based',
        forceAtlas2Based: {
          gravitationalConstant: -50,
          centralGravity: 0.01,
          springLength: 200,
          springConstant: 0.08,
          damping: 0.4,
        },
        stabilization: {
          enabled: true,
          iterations: 100,
        },
      },
      interaction: {
        hover: true,
        tooltipDelay: 100,
        zoomView: true,
        dragView: true,
      },
      layout: {
        improvedLayout: true,
      },
    }

    // Destroy existing network if it exists
    if (networkRef.current) {
      networkRef.current.destroy()
    }

    // Create new network
    networkRef.current = new Network(containerRef.current, data, options)

    // Add event listeners
    networkRef.current.on('click', (params) => {
      if (params.nodes.length > 0) {
        const nodeId = params.nodes[0]
        const site = sites.find((s) => s.id === nodeId)
        if (site) {
          console.log('Clicked site:', site)
        }
      }
      if (params.edges.length > 0) {
        const edgeId = params.edges[0]
        const path = paths.find((p) => p.id === edgeId)
        if (path) {
          console.log('Clicked path:', path)
        }
      }
    })

    return () => {
      if (networkRef.current) {
        networkRef.current.destroy()
        networkRef.current = null
      }
    }
  }, [sites, paths, sitesLoading, pathsLoading])

  if (sitesLoading || pathsLoading) {
    return (
      <div className="flex items-center justify-center" style={{ height }}>
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500" />
      </div>
    )
  }

  if (sites.length === 0) {
    return (
      <div className="flex items-center justify-center" style={{ height }}>
        <p className="text-gray-500 dark:text-gray-400">
          No sites configured. Create sites to see the network topology.
        </p>
      </div>
    )
  }

  return (
    <div>
      <div ref={containerRef} style={{ height }} className="border border-gray-200 dark:border-gray-700 rounded-lg" />
      <div className="mt-4 flex items-center justify-center space-x-6 text-sm">
        <div className="flex items-center">
          <div className="w-4 h-4 rounded-full bg-green-500 mr-2" />
          <span className="text-gray-700 dark:text-gray-300">Active</span>
        </div>
        <div className="flex items-center">
          <div className="w-4 h-4 rounded-full bg-yellow-500 mr-2" />
          <span className="text-gray-700 dark:text-gray-300">Degraded</span>
        </div>
        <div className="flex items-center">
          <div className="w-4 h-4 rounded-full bg-red-500 mr-2" />
          <span className="text-gray-700 dark:text-gray-300">Down</span>
        </div>
      </div>
    </div>
  )
}

function getNodeColor(status: string): string {
  switch (status) {
    case 'Active':
      return '#10b981' // green
    case 'Degraded':
      return '#f59e0b' // yellow
    case 'Down':
      return '#ef4444' // red
    default:
      return '#6b7280' // gray
  }
}

function getEdgeColor(status: string, qualityScore: number): object {
  let color = '#6b7280' // default gray

  if (status === 'Active') {
    if (qualityScore >= 80) {
      color = '#10b981' // green - good quality
    } else if (qualityScore >= 50) {
      color = '#f59e0b' // yellow - degraded quality
    } else {
      color = '#ef4444' // red - poor quality
    }
  } else if (status === 'Degraded') {
    color = '#f59e0b' // yellow
  } else if (status === 'Down') {
    color = '#ef4444' // red
  }

  return {
    color,
    highlight: color,
    hover: color,
  }
}
