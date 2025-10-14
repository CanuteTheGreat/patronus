import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import { format } from 'date-fns'

interface MetricData {
  timestamp: string
  throughput: number
  latency: number
  packetLoss: number
}

interface Props {
  data: MetricData[]
}

export default function MetricsChart({ data }: Props) {
  const formattedData = data.map(item => ({
    ...item,
    time: format(new Date(item.timestamp), 'HH:mm:ss'),
    throughputMbps: (item.throughput / 1_000_000).toFixed(2),
    packetLossPercent: (item.packetLoss * 100).toFixed(2),
  }))

  return (
    <ResponsiveContainer width="100%" height={300}>
      <LineChart data={formattedData}>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="time" />
        <YAxis yAxisId="left" />
        <YAxis yAxisId="right" orientation="right" />
        <Tooltip />
        <Legend />
        <Line
          yAxisId="left"
          type="monotone"
          dataKey="throughputMbps"
          stroke="#0ea5e9"
          name="Throughput (Mbps)"
          strokeWidth={2}
        />
        <Line
          yAxisId="left"
          type="monotone"
          dataKey="latency"
          stroke="#10b981"
          name="Latency (ms)"
          strokeWidth={2}
        />
        <Line
          yAxisId="right"
          type="monotone"
          dataKey="packetLossPercent"
          stroke="#ef4444"
          name="Packet Loss (%)"
          strokeWidth={2}
        />
      </LineChart>
    </ResponsiveContainer>
  )
}
