export default function StatsCards({ vms }) {
  const runningVms = vms.filter(vm => vm.status === 'running').length
  const pausedVms = vms.filter(vm => vm.status === 'paused').length
  const stoppedVms = vms.filter(vm => vm.status === 'stopped' || vm.status === 'failed' || vm.status === 'crashed').length

  return (
    <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
      <div className="p-6 bg-gradient-to-br from-gray-900/80 to-gray-950/80 border border-green-900/30 rounded-lg backdrop-blur-sm">
        <div className="text-green-600 text-sm mb-2">TOTAL INSTANCES</div>
        <div className="text-4xl font-bold text-green-400">{vms.length}</div>
      </div>
      <div className="p-6 bg-gradient-to-br from-gray-900/80 to-gray-950/80 border border-green-900/30 rounded-lg backdrop-blur-sm">
        <div className="text-green-600 text-sm mb-2">RUNNING</div>
        <div className="text-4xl font-bold text-emerald-400">{runningVms}</div>
      </div>
      <div className="p-6 bg-gradient-to-br from-gray-900/80 to-gray-950/80 border border-green-900/30 rounded-lg backdrop-blur-sm">
        <div className="text-green-600 text-sm mb-2">PAUSED</div>
        <div className="text-4xl font-bold text-yellow-400">{pausedVms}</div>
      </div>
      <div className="p-6 bg-gradient-to-br from-gray-900/80 to-gray-950/80 border border-green-900/30 rounded-lg backdrop-blur-sm">
        <div className="text-green-600 text-sm mb-2">STOPPED</div>
        <div className="text-4xl font-bold text-red-400">{stoppedVms}</div>
      </div>
    </div>
  )
}
