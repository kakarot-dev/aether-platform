import { AreaChart, Area, XAxis, YAxis, ResponsiveContainer, Tooltip } from 'recharts'
import { useTelemetry } from '../context/TelemetryContext'

export default function CpuGraph({ vmId }) {
  const { getMetrics } = useTelemetry()
  const metrics = getMetrics(vmId)

  // Transform data for recharts
  const data = metrics.map((m, i) => ({
    index: i,
    cpu: m.cpu,
    memory: m.memory,
  }))

  if (data.length < 2) {
    return (
      <div className="h-24 flex items-center justify-center text-green-700 text-xs">
        Collecting metrics...
      </div>
    )
  }

  return (
    <div className="h-24">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 5, right: 5, left: 0, bottom: 5 }}>
          <defs>
            <linearGradient id={`cpuGradient-${vmId}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#10b981" stopOpacity={0.4} />
              <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
            </linearGradient>
            <linearGradient id={`memGradient-${vmId}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4} />
              <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
            </linearGradient>
          </defs>
          <XAxis dataKey="index" hide />
          <YAxis domain={[0, 100]} hide />
          <Tooltip
            contentStyle={{
              backgroundColor: '#111827',
              border: '1px solid #065f46',
              borderRadius: '4px',
              fontSize: '12px',
            }}
            labelStyle={{ display: 'none' }}
            formatter={(value, name) => [
              `${value.toFixed(1)}%`,
              name === 'cpu' ? 'CPU' : 'Memory'
            ]}
          />
          <Area
            type="monotone"
            dataKey="cpu"
            stroke="#10b981"
            strokeWidth={2}
            fill={`url(#cpuGradient-${vmId})`}
            isAnimationActive={false}
          />
          <Area
            type="monotone"
            dataKey="memory"
            stroke="#3b82f6"
            strokeWidth={2}
            fill={`url(#memGradient-${vmId})`}
            isAnimationActive={false}
          />
        </AreaChart>
      </ResponsiveContainer>
      <div className="flex justify-center gap-4 text-xs mt-1">
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 bg-emerald-500 rounded-full" />
          <span className="text-green-600">CPU</span>
        </span>
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 bg-blue-500 rounded-full" />
          <span className="text-green-600">Memory</span>
        </span>
      </div>
    </div>
  )
}
