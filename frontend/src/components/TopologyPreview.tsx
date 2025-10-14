import { Link } from 'react-router-dom'
import { ArrowRight } from 'lucide-react'

export default function TopologyPreview() {
  return (
    <div className="flex flex-col items-center justify-center h-64 border-2 border-dashed border-gray-300 rounded-lg">
      <p className="text-gray-500 mb-4">View full network topology</p>
      <Link
        to="/topology"
        className="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors"
      >
        Go to Topology
        <ArrowRight className="h-4 w-4" />
      </Link>
    </div>
  )
}
