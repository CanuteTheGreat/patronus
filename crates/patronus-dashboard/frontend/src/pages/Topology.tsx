import NetworkTopology from '../components/NetworkTopology'

export default function Topology() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100">
          Network Topology
        </h1>
        <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
          Visualize your SD-WAN network topology and path quality
        </p>
      </div>

      <div className="card">
        <NetworkTopology height={700} />
      </div>

      <div className="card">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
          Topology Information
        </h3>
        <div className="space-y-4 text-sm text-gray-700 dark:text-gray-300">
          <div>
            <h4 className="font-medium mb-2">Node Colors:</h4>
            <ul className="list-disc list-inside space-y-1 ml-2">
              <li>Green: Site is active and healthy</li>
              <li>Yellow: Site is degraded</li>
              <li>Red: Site is down</li>
            </ul>
          </div>
          <div>
            <h4 className="font-medium mb-2">Edge Colors:</h4>
            <ul className="list-disc list-inside space-y-1 ml-2">
              <li>Green: Path quality score ≥ 80 (excellent)</li>
              <li>Yellow: Path quality score 50-79 (degraded)</li>
              <li>Red: Path quality score &lt; 50 (poor) or path is down</li>
            </ul>
          </div>
          <div>
            <h4 className="font-medium mb-2">Interactions:</h4>
            <ul className="list-disc list-inside space-y-1 ml-2">
              <li>Click and drag to pan the view</li>
              <li>Scroll to zoom in/out</li>
              <li>Hover over nodes and edges to see detailed information</li>
              <li>Click on nodes or edges to view more details (console log)</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  )
}
