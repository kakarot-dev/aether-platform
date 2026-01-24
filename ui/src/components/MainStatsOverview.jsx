export default function MainStatsOverview({ vms, systemInfo }) {
  const running = vms.filter(vm => vm.status === 'running').length
  const paused = vms.filter(vm => vm.status === 'paused').length
  const stopped = vms.filter(vm => ['stopped', 'failed', 'crashed'].includes(vm.status)).length
  const total = vms.length

  // Calculate aggregate resource usage from running VMs with stats
  const runningWithStats = vms.filter(vm => vm.status === 'running' && vm.stats)
  const avgCpu = runningWithStats.length > 0
    ? runningWithStats.reduce((sum, vm) => sum + (vm.stats?.cpu_usage_percent || 0), 0) / runningWithStats.length
    : 0
  const avgMemory = runningWithStats.length > 0
    ? runningWithStats.reduce((sum, vm) => sum + (vm.stats?.memory_usage_percent || 0), 0) / runningWithStats.length
    : 0

  return (
    <div className="bg-gray-900/40 border border-green-900/30 rounded-lg p-4 mb-6">
      <div className="flex flex-wrap items-center gap-6">
        {/* VM Status Counts */}
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 bg-emerald-500 rounded-full animate-pulse"></span>
            <span className="text-xl font-bold text-emerald-400">{running}</span>
            <span className="text-xs text-green-700">RUNNING</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 bg-yellow-500 rounded-full"></span>
            <span className="text-xl font-bold text-yellow-400">{paused}</span>
            <span className="text-xs text-green-700">PAUSED</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 bg-red-500 rounded-full"></span>
            <span className="text-xl font-bold text-red-400">{stopped}</span>
            <span className="text-xs text-green-700">STOPPED</span>
          </div>
        </div>

        {/* Divider */}
        <div className="h-8 w-px bg-green-900/50"></div>

        {/* Resource Usage */}
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-3">
            <span className="text-xs text-green-700">CPU</span>
            <div className="w-24 h-2 bg-gray-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-emerald-600 to-green-500 transition-all duration-300"
                style={{ width: `${Math.min(avgCpu, 100)}%` }}
              />
            </div>
            <span className="text-xs text-green-400 font-mono w-12">{avgCpu.toFixed(1)}%</span>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xs text-green-700">MEM</span>
            <div className="w-24 h-2 bg-gray-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-cyan-600 to-blue-500 transition-all duration-300"
                style={{ width: `${Math.min(avgMemory, 100)}%` }}
              />
            </div>
            <span className="text-xs text-green-400 font-mono w-12">{avgMemory.toFixed(1)}%</span>
          </div>
        </div>

        {/* Divider */}
        <div className="h-8 w-px bg-green-900/50"></div>

        {/* System Info */}
        {systemInfo && (
          <div className="flex items-center gap-4 text-xs text-green-700">
            <span>Host: <span className="text-green-500">{systemInfo.host_ip}</span></span>
            <span>Bridge: <span className="text-green-500">{systemInfo.bridge_ip}</span></span>
            <span>Subnet: <span className="text-green-500">{systemInfo.vm_subnet}</span></span>
          </div>
        )}
      </div>
    </div>
  )
}
