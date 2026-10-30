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
      <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100">Traffic Analysis</h1>

      {data.trafficStats.map((stat) => (
        <div key={stat.siteId} className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-xl font-semibold text-gray-900 dark:text-gray-100">{stat.siteName}</h2>
              <p className="text-sm text-gray-600 dark:text-gray-300">Site ID: {stat.siteId}</p>
            </div>
            <div className="text-right">
              <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
                {formatBytes(stat.totalBytes)}
              </p>
              <p className="text-sm text-gray-600 dark:text-gray-300">Total Traffic</p>
            </div>
          </div>

          {/* Application Traffic Chart */}
          <div className="mb-6">
            <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-4">
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
            <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-4">
              Application Details
            </h3>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                <thead className="bg-gray-50 dark:bg-gray-900">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Application
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Bytes
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Packets
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Percentage
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                  {stat.applications.map((app) => (
                    <tr key={app.name}>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-gray-100">
                        {app.name}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600 dark:text-gray-300">
                        {formatBytes(app.bytes)}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600 dark:text-gray-300">
                        {app.packets.toLocaleString()}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600 dark:text-gray-300">
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
