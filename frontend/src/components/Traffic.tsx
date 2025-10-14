import { useQuery, gql } from '@apollo/client'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'

const TRAFFIC_QUERY = gql`
  query Traffic {
    trafficStats {
      siteId
      siteName
      totalBytes
      totalPackets
      applications {
        name
        bytes
        packets
        percentage
      }
    }
  }
`

interface Application {
  name: string
  bytes: number
  packets: number
  percentage: number
}

interface TrafficStat {
  siteId: string
  siteName: string
  totalBytes: number
  totalPackets: number
  applications: Application[]
}

interface TrafficData {
  trafficStats: TrafficStat[]
}

export default function Traffic() {
  const { loading, error, data } = useQuery<TrafficData>(TRAFFIC_QUERY, {
    pollInterval: 10000,
  })

  if (loading) return <div>Loading traffic data...</div>
  if (error) return <div>Error: {error.message}</div>
  if (!data) return <div>No data</div>

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-gray-900">Traffic Analysis</h1>

      {data.trafficStats.map((stat) => (
        <div key={stat.siteId} className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-xl font-semibold text-gray-900">{stat.siteName}</h2>
              <p className="text-sm text-gray-600">Site ID: {stat.siteId}</p>
            </div>
            <div className="text-right">
              <p className="text-2xl font-bold text-gray-900">
                {formatBytes(stat.totalBytes)}
              </p>
              <p className="text-sm text-gray-600">Total Traffic</p>
            </div>
          </div>

          {/* Application Traffic Chart */}
          <div className="mb-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">
              Traffic by Application
            </h3>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={stat.applications}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip formatter={(value: number) => formatBytes(value)} />
                <Legend />
                <Bar dataKey="bytes" fill="#0ea5e9" name="Bytes" />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Application Table */}
          <div>
            <h3 className="text-lg font-medium text-gray-900 mb-4">
              Application Details
            </h3>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Application
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Bytes
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Packets
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Percentage
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {stat.applications.map((app) => (
                    <tr key={app.name}>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                        {app.name}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600">
                        {formatBytes(app.bytes)}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600">
                        {app.packets.toLocaleString()}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600">
                        {app.percentage.toFixed(2)}%
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}
