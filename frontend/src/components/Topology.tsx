import { useEffect, useRef } from 'react'
import { useQuery, gql } from '@apollo/client'
import ForceGraph2D from 'react-force-graph-2d'

const TOPOLOGY_QUERY = gql`
  query Topology {
    sites {
      id
      name
      location
      status
    }
    links {
      id
      sourceId
      targetId
      status
      latency
      bandwidth
      utilization
    }
  }
`

interface Site {
  id: string
  name: string
  location: string
  status: 'active' | 'inactive' | 'degraded'
}

interface Link {
  id: string
  sourceId: string
  targetId: string
  status: 'healthy' | 'degraded' | 'down'
  latency: number
  bandwidth: number
  utilization: number
}

interface TopologyData {
  sites: Site[]
  links: Link[]
}

export default function Topology() {
  const { loading, error, data } = useQuery<TopologyData>(TOPOLOGY_QUERY, {
    pollInterval: 10000,
  })

  const graphRef = useRef<any>()

  useEffect(() => {
    if (graphRef.current) {
      graphRef.current.d3Force('charge').strength(-400)
      graphRef.current.d3Force('link').distance(200)
    }
  }, [])

  if (loading) return <div>Loading topology...</div>
  if (error) return <div>Error: {error.message}</div>
  if (!data) return <div>No data</div>

  const graphData = {
    nodes: data.sites.map(site => ({
      id: site.id,
      name: site.name,
      location: site.location,
      status: site.status,
    })),
    links: data.links.map(link => ({
      source: link.sourceId,
      target: link.targetId,
      status: link.status,
      latency: link.latency,
      bandwidth: link.bandwidth,
      utilization: link.utilization,
    })),
  }

  const getNodeColor = (status: string) => {
    switch (status) {
      case 'active':
        return '#10b981'
      case 'degraded':
        return '#f59e0b'
      case 'inactive':
        return '#ef4444'
      default:
        return '#6b7280'
    }
  }

  const getLinkColor = (status: string) => {
    switch (status) {
      case 'healthy':
        return '#10b981'
      case 'degraded':
        return '#f59e0b'
      case 'down':
        return '#ef4444'
      default:
        return '#6b7280'
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">Network Topology</h1>
        <div className="flex gap-4">
          <div className="flex items-center gap-2">
            <div className="h-3 w-3 rounded-full bg-green-500" />
            <span className="text-sm text-gray-600">Active</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="h-3 w-3 rounded-full bg-yellow-500" />
            <span className="text-sm text-gray-600">Degraded</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="h-3 w-3 rounded-full bg-red-500" />
            <span className="text-sm text-gray-600">Down</span>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow" style={{ height: '700px' }}>
        <ForceGraph2D
          ref={graphRef}
          graphData={graphData}
          nodeLabel={(node: any) => `${node.name}\n${node.location}`}
          nodeColor={(node: any) => getNodeColor(node.status)}
          nodeRelSize={8}
          linkColor={(link: any) => getLinkColor(link.status)}
          linkWidth={2}
          linkLabel={(link: any) =>
            `Latency: ${link.latency}ms\nBandwidth: ${link.bandwidth}Mbps\nUtilization: ${(link.utilization * 100).toFixed(1)}%`
          }
          linkDirectionalParticles={2}
          linkDirectionalParticleSpeed={0.005}
          backgroundColor="#ffffff"
        />
      </div>
    </div>
  )
}
