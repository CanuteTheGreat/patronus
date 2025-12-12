import { useState, useMemo } from 'react'
import { useQuery, useSubscription } from '@apollo/client'
import { GET_METRICS, GET_METRICS_HISTORY, METRICS_SUBSCRIPTION } from '../graphql/queries'
import type { Metrics } from '../types'
import { formatNumber } from '../types'
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
import {
  ArrowDownTrayIcon,
  ArrowPathIcon,
  ArrowTrendingUpIcon,
  ArrowTrendingDownIcon,
  ClockIcon,
  CpuChipIcon,
  CircleStackIcon,
} from '@heroicons/react/24/outline'
import dayjs from 'dayjs'
import Loading from '../components/Loading'
import toast from 'react-hot-toast'

type TimeRange = '15m' | '1h' | '6h' | '24h' | '7d' | '30d'

export default function MetricsPage() {
  const [timeRange, setTimeRange] = useState<TimeRange>('1h')
  const [autoRefresh, setAutoRefresh] = useState(true)

  const getTimeRange = () => {
    const to = new Date()
    const from = new Date()

    switch (timeRange) {
      case '15m':
        from.setMinutes(from.getMinutes() - 15)
        return { from, to, interval: 15 }
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
      case '30d':
        from.setDate(from.getDate() - 30)
        return { from, to, interval: 14400 }
      default:
        from.setHours(from.getHours() - 1)
        return { from, to, interval: 60 }
    }
  }

  const { from, to, interval } = getTimeRange()

  const { data: currentData } = useQuery(GET_METRICS)
  const { data, loading, refetch } = useQuery(GET_METRICS_HISTORY, {
    variables: {
      from: from.toISOString(),
      to: to.toISOString(),
      intervalSeconds: interval,
    },
    pollInterval: autoRefresh ? 30000 : 0,
  })

  // Subscribe to real-time metrics
  useSubscription(METRICS_SUBSCRIPTION, {
    variables: { intervalSeconds: 10 },
    skip: !autoRefresh,
  })

  const current: Metrics | null = currentData?.metrics || null
  const metrics: Metrics[] = data?.metricsHistory || []

  // Calculate summary statistics
  const stats = useMemo(() => {
    if (metrics.length === 0) return null

    const throughputs = metrics.map(m => m.throughputMbps)
    const latencies = metrics.map(m => m.avgLatencyMs)
    const losses = metrics.map(m => m.avgPacketLoss)
    const cpus = metrics.map(m => m.cpuUsage)
    const mems = metrics.map(m => m.memoryUsage)

    return {
      throughput: {
        avg: throughputs.reduce((a, b) => a + b, 0) / throughputs.length,
        max: Math.max(...throughputs),
        min: Math.min(...throughputs),
      },
      latency: {
        avg: latencies.reduce((a, b) => a + b, 0) / latencies.length,
        max: Math.max(...latencies),
        min: Math.min(...latencies),
      },
      loss: {
        avg: losses.reduce((a, b) => a + b, 0) / losses.length,
        max: Math.max(...losses),
      },
      cpu: {
        avg: cpus.reduce((a, b) => a + b, 0) / cpus.length,
        max: Math.max(...cpus),
      },
      memory: {
        avg: mems.reduce((a, b) => a + b, 0) / mems.length,
        max: Math.max(...mems),
      },
    }
  }, [metrics])

  const chartData = metrics.map((m) => ({
    time: dayjs(m.timestamp).format(timeRange === '7d' || timeRange === '30d' ? 'MMM D' : 'HH:mm'),
    timestamp: m.timestamp,
    throughput: m.throughputMbps,
    packets: m.packetsPerSecond,
    flows: m.activeFlows,
    latency: m.avgLatencyMs,
    loss: m.avgPacketLoss,
    cpu: m.cpuUsage,
    memory: m.memoryUsage,
  }))

  const handleExport = (format: 'csv' | 'json') => {
    if (metrics.length === 0) {
      toast.error('No data to export')
      return
    }

    let content: string
    let filename: string
    let mimeType: string

    if (format === 'csv') {
      const headers = [
        'Timestamp',
        'Throughput (Mbps)',
        'Packets/sec',
        'Active Flows',
        'Avg Latency (ms)',
        'Packet Loss (%)',
        'CPU Usage (%)',
        'Memory Usage (%)',
      ]
      const rows = metrics.map((m) => [
        m.timestamp,
        m.throughputMbps.toFixed(2),
        m.packetsPerSecond,
        m.activeFlows,
        m.avgLatencyMs.toFixed(2),
        m.avgPacketLoss.toFixed(4),
        m.cpuUsage.toFixed(2),
        m.memoryUsage.toFixed(2),
      ])
      content = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n')
      filename = `patronus-metrics-${timeRange}-${dayjs().format('YYYY-MM-DD-HHmm')}.csv`
      mimeType = 'text/csv'
    } else {
      content = JSON.stringify(metrics, null, 2)
      filename = `patronus-metrics-${timeRange}-${dayjs().format('YYYY-MM-DD-HHmm')}.json`
      mimeType = 'application/json'
    }

    const blob = new Blob([content], { type: mimeType })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)

    toast.success(`Exported ${metrics.length} data points to ${format.toUpperCase()}`)
  }

  if (loading && metrics.length === 0) {
    return <Loading message="Loading metrics..." />
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100">
            Metrics
          </h1>
          <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
            Network performance metrics and analytics
          </p>
        </div>
        <div className="mt-4 md:mt-0 flex items-center space-x-4">
          {/* Time Range Selector */}
          <div className="flex space-x-1 bg-gray-100 dark:bg-gray-700 rounded-lg p-1">
            {(['15m', '1h', '6h', '24h', '7d', '30d'] as TimeRange[]).map((range) => (
              <button
                key={range}
                onClick={() => setTimeRange(range)}
                className={`px-3 py-1 rounded-md text-sm font-medium transition-colors ${
                  timeRange === range
                    ? 'bg-white dark:bg-gray-600 text-blue-600 dark:text-blue-400 shadow-sm'
                    : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200'
                }`}
              >
                {range}
              </button>
            ))}
          </div>

          {/* Auto Refresh Toggle */}
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`btn ${autoRefresh ? 'btn-primary' : 'btn-secondary'} flex items-center`}
            title={autoRefresh ? 'Auto-refresh enabled' : 'Auto-refresh disabled'}
          >
            <ArrowPathIcon className={`w-5 h-5 ${autoRefresh ? 'animate-spin' : ''}`} />
          </button>

          {/* Export Menu */}
          <div className="relative group">
            <button className="btn btn-secondary flex items-center">
              <ArrowDownTrayIcon className="w-5 h-5 mr-2" />
              Export
            </button>
            <div className="absolute right-0 mt-2 w-40 bg-white dark:bg-gray-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-10">
              <button
                onClick={() => handleExport('csv')}
                className="w-full px-4 py-2 text-left text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-t-lg"
              >
                Export as CSV
              </button>
              <button
                onClick={() => handleExport('json')}
                className="w-full px-4 py-2 text-left text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-b-lg"
              >
                Export as JSON
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Current Metrics */}
      {current && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
          <CurrentMetricCard
            title="Throughput"
            value={`${current.throughputMbps.toFixed(1)} Mbps`}
            icon={<ArrowTrendingUpIcon className="w-5 h-5" />}
            color="blue"
          />
          <CurrentMetricCard
            title="Packets/sec"
            value={formatNumber(current.packetsPerSecond)}
            icon={<ArrowTrendingUpIcon className="w-5 h-5" />}
            color="green"
          />
          <CurrentMetricCard
            title="Active Flows"
            value={formatNumber(current.activeFlows)}
            icon={<CircleStackIcon className="w-5 h-5" />}
            color="purple"
          />
          <CurrentMetricCard
            title="Latency"
            value={`${current.avgLatencyMs.toFixed(2)} ms`}
            icon={<ClockIcon className="w-5 h-5" />}
            color={current.avgLatencyMs > 100 ? 'red' : 'green'}
          />
          <CurrentMetricCard
            title="Packet Loss"
            value={`${current.avgPacketLoss.toFixed(3)}%`}
            icon={current.avgPacketLoss > 1 ? <ArrowTrendingDownIcon className="w-5 h-5" /> : <ArrowTrendingUpIcon className="w-5 h-5" />}
            color={current.avgPacketLoss > 1 ? 'red' : current.avgPacketLoss > 0.5 ? 'yellow' : 'green'}
          />
          <CurrentMetricCard
            title="CPU / Memory"
            value={`${current.cpuUsage.toFixed(0)}% / ${current.memoryUsage.toFixed(0)}%`}
            icon={<CpuChipIcon className="w-5 h-5" />}
            color={current.cpuUsage > 90 || current.memoryUsage > 90 ? 'red' : 'blue'}
          />
        </div>
      )}

      {/* Summary Statistics */}
      {stats && (
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
            Summary Statistics ({timeRange})
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <SummaryCard
              title="Throughput"
              avg={`${stats.throughput.avg.toFixed(1)} Mbps`}
              max={`${stats.throughput.max.toFixed(1)} Mbps`}
              min={`${stats.throughput.min.toFixed(1)} Mbps`}
            />
            <SummaryCard
              title="Latency"
              avg={`${stats.latency.avg.toFixed(2)} ms`}
              max={`${stats.latency.max.toFixed(2)} ms`}
              min={`${stats.latency.min.toFixed(2)} ms`}
            />
            <SummaryCard
              title="Packet Loss"
              avg={`${stats.loss.avg.toFixed(3)}%`}
              max={`${stats.loss.max.toFixed(3)}%`}
            />
            <SummaryCard
              title="CPU Usage"
              avg={`${stats.cpu.avg.toFixed(1)}%`}
              max={`${stats.cpu.max.toFixed(1)}%`}
            />
            <SummaryCard
              title="Memory Usage"
              avg={`${stats.memory.avg.toFixed(1)}%`}
              max={`${stats.memory.max.toFixed(1)}%`}
            />
          </div>
        </div>
      )}

      {metrics.length === 0 ? (
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
              Network Throughput
            </h3>
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="throughputGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="time" stroke="#9ca3af" fontSize={12} />
                <YAxis stroke="#9ca3af" fontSize={12} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1f2937',
                    border: 'none',
                    borderRadius: '8px',
                    color: '#f3f4f6',
                  }}
                />
                <Legend />
                <Area
                  type="monotone"
                  dataKey="throughput"
                  stroke="#3b82f6"
                  fill="url(#throughputGradient)"
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
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="time" stroke="#9ca3af" fontSize={12} />
                  <YAxis stroke="#9ca3af" fontSize={12} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#1f2937',
                      border: 'none',
                      borderRadius: '8px',
                      color: '#f3f4f6',
                    }}
                  />
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
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="time" stroke="#9ca3af" fontSize={12} />
                  <YAxis stroke="#9ca3af" fontSize={12} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#1f2937',
                      border: 'none',
                      borderRadius: '8px',
                      color: '#f3f4f6',
                    }}
                  />
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
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="time" stroke="#9ca3af" fontSize={12} />
                  <YAxis stroke="#9ca3af" fontSize={12} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#1f2937',
                      border: 'none',
                      borderRadius: '8px',
                      color: '#f3f4f6',
                    }}
                  />
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
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="time" stroke="#9ca3af" fontSize={12} />
                  <YAxis stroke="#9ca3af" fontSize={12} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#1f2937',
                      border: 'none',
                      borderRadius: '8px',
                      color: '#f3f4f6',
                    }}
                  />
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
          <div className="card">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
              System Resources
            </h3>
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="cpuGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="memGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="time" stroke="#9ca3af" fontSize={12} />
                <YAxis stroke="#9ca3af" fontSize={12} domain={[0, 100]} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1f2937',
                    border: 'none',
                    borderRadius: '8px',
                    color: '#f3f4f6',
                  }}
                />
                <Legend />
                <Area
                  type="monotone"
                  dataKey="cpu"
                  stroke="#3b82f6"
                  fill="url(#cpuGradient)"
                  name="CPU (%)"
                />
                <Area
                  type="monotone"
                  dataKey="memory"
                  stroke="#10b981"
                  fill="url(#memGradient)"
                  name="Memory (%)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}
    </div>
  )
}

function CurrentMetricCard({
  title,
  value,
  icon,
  color,
}: {
  title: string
  value: string
  icon: React.ReactNode
  color: 'blue' | 'green' | 'yellow' | 'red' | 'purple'
}) {
  const colorClasses = {
    blue: 'text-blue-600 dark:text-blue-400 bg-blue-100 dark:bg-blue-900',
    green: 'text-green-600 dark:text-green-400 bg-green-100 dark:bg-green-900',
    yellow: 'text-yellow-600 dark:text-yellow-400 bg-yellow-100 dark:bg-yellow-900',
    red: 'text-red-600 dark:text-red-400 bg-red-100 dark:bg-red-900',
    purple: 'text-purple-600 dark:text-purple-400 bg-purple-100 dark:bg-purple-900',
  }

  return (
    <div className="card">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs text-gray-500 dark:text-gray-400">{title}</p>
          <p className="text-lg font-bold text-gray-900 dark:text-gray-100">{value}</p>
        </div>
        <div className={`p-2 rounded-full ${colorClasses[color]}`}>
          {icon}
        </div>
      </div>
    </div>
  )
}

function SummaryCard({
  title,
  avg,
  max,
  min,
}: {
  title: string
  avg: string
  max: string
  min?: string
}) {
  return (
    <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4">
      <p className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">{title}</p>
      <div className="space-y-1">
        <div className="flex justify-between text-sm">
          <span className="text-gray-500 dark:text-gray-400">Avg:</span>
          <span className="font-medium text-gray-900 dark:text-gray-100">{avg}</span>
        </div>
        <div className="flex justify-between text-sm">
          <span className="text-gray-500 dark:text-gray-400">Max:</span>
          <span className="font-medium text-red-600 dark:text-red-400">{max}</span>
        </div>
        {min && (
          <div className="flex justify-between text-sm">
            <span className="text-gray-500 dark:text-gray-400">Min:</span>
            <span className="font-medium text-green-600 dark:text-green-400">{min}</span>
          </div>
        )}
      </div>
    </div>
  )
}
