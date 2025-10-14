import { useState } from 'react'
import { useQuery } from '@apollo/client'
import { GET_METRICS_HISTORY } from '../graphql/queries'
import type { Metrics } from '../types'
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts'
import dayjs from 'dayjs'

export default function MetricsPage() {
  const [timeRange, setTimeRange] = useState('1h')

  const getTimeRange = () => {
    const to = new Date()
    const from = new Date()

    switch (timeRange) {
      case '1h':
        from.setHours(from.getHours() - 1)
        return { from, to, interval: 60 }
      case '6h':
        from.setHours(from.getHours() - 6)
        return { from, to, interval: 300 }
      case '24h':
        from.setHours(from.getHours() - 24)
        return { from, to, interval: 600 }
      case '7d':
        from.setDate(from.getDate() - 7)
        return { from, to, interval: 3600 }
      default:
        from.setHours(from.getHours() - 1)
        return { from, to, interval: 60 }
    }
  }

  const { from, to, interval } = getTimeRange()

  const { data, loading } = useQuery(GET_METRICS_HISTORY, {
    variables: {
      from: from.toISOString(),
      to: to.toISOString(),
      intervalSeconds: interval,
    },
    pollInterval: 30000, // Refresh every 30 seconds
  })

  const metrics: Metrics[] = data?.metricsHistory || []

  const chartData = metrics.map((m) => ({
    time: dayjs(m.timestamp).format('HH:mm'),
    throughput: m.throughputMbps,
    packets: m.packetsPerSecond,
    flows: m.activeFlows,
    latency: m.avgLatencyMs,
    loss: m.avgPacketLoss,
    cpu: m.cpuUsage,
    memory: m.memoryUsage,
  }))

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100">
            Metrics
          </h1>
          <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
            Network performance metrics and analytics
          </p>
        </div>
        <div className="flex space-x-2">
          {['1h', '6h', '24h', '7d'].map((range) => (
            <button
              key={range}
              onClick={() => setTimeRange(range)}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                timeRange === range
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600'
              }`}
            >
              {range}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <div className="flex justify-center py-12">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500" />
        </div>
      ) : metrics.length === 0 ? (
        <div className="card text-center py-12">
          <p className="text-gray-500 dark:text-gray-400">
            No metrics data available for this time range
          </p>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Throughput */}
          <div className="card">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
              Throughput
            </h3>
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Area
                  type="monotone"
                  dataKey="throughput"
                  stroke="#3b82f6"
                  fill="#3b82f6"
                  fillOpacity={0.3}
                  name="Throughput (Mbps)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Packets and Flows */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
                Packets per Second
              </h3>
              <ResponsiveContainer width="100%" height={250}>
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="time" />
                  <YAxis />
                  <Tooltip />
                  <Line
                    type="monotone"
                    dataKey="packets"
                    stroke="#10b981"
                    strokeWidth={2}
                    dot={false}
                    name="Packets/sec"
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>

            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
                Active Flows
              </h3>
              <ResponsiveContainer width="100%" height={250}>
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="time" />
                  <YAxis />
                  <Tooltip />
                  <Line
                    type="monotone"
                    dataKey="flows"
                    stroke="#f59e0b"
                    strokeWidth={2}
                    dot={false}
                    name="Active Flows"
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Latency and Packet Loss */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
                Average Latency
              </h3>
              <ResponsiveContainer width="100%" height={250}>
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="time" />
                  <YAxis />
                  <Tooltip />
                  <Line
                    type="monotone"
                    dataKey="latency"
                    stroke="#8b5cf6"
                    strokeWidth={2}
                    dot={false}
                    name="Latency (ms)"
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>

            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
                Packet Loss
              </h3>
              <ResponsiveContainer width="100%" height={250}>
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="time" />
                  <YAxis />
                  <Tooltip />
                  <Line
                    type="monotone"
                    dataKey="loss"
                    stroke="#ef4444"
                    strokeWidth={2}
                    dot={false}
                    name="Packet Loss (%)"
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* System Resources */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
                CPU Usage
              </h3>
              <ResponsiveContainer width="100%" height={250}>
                <AreaChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="time" />
                  <YAxis domain={[0, 100]} />
                  <Tooltip />
                  <Area
                    type="monotone"
                    dataKey="cpu"
                    stroke="#3b82f6"
                    fill="#3b82f6"
                    fillOpacity={0.3}
                    name="CPU (%)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
                Memory Usage
              </h3>
              <ResponsiveContainer width="100%" height={250}>
                <AreaChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="time" />
                  <YAxis domain={[0, 100]} />
                  <Tooltip />
                  <Area
                    type="monotone"
                    dataKey="memory"
                    stroke="#10b981"
                    fill="#10b981"
                    fillOpacity={0.3}
                    name="Memory (%)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
