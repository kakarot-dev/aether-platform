export default function VmListCompact({ vms, selectedVmId, onSelectVm }) {
  const getStatusColor = (status) => {
    switch (status) {
      case 'running':
        return 'bg-emerald-500'
      case 'paused':
        return 'bg-yellow-500'
      case 'stopped':
      case 'failed':
      case 'crashed':
        return 'bg-red-500'
      default:
        return 'bg-gray-500'
    }
  }

  const getStatusRing = (status) => {
    switch (status) {
      case 'running':
        return 'ring-emerald-500/30'
      case 'paused':
        return 'ring-yellow-500/30'
      default:
        return 'ring-red-500/30'
    }
  }

  return (
    <div className="h-full flex flex-col">
      <div className="px-3 py-2 border-b border-green-900/30">
        <h2 className="text-xs font-semibold text-green-600 tracking-wider">
          INSTANCES ({vms.length})
        </h2>
      </div>
      <div className="flex-1 overflow-y-auto">
        {vms.length === 0 ? (
          <div className="p-4 text-center text-green-800 text-sm">
            No VMs deployed
          </div>
        ) : (
          <div className="p-2 space-y-1">
            {vms.map((vm) => (
              <button
                key={vm.id}
                onClick={() => onSelectVm(vm.id)}
                className={`w-full text-left px-3 py-2 rounded transition-all duration-150 flex items-center gap-3 ${
                  selectedVmId === vm.id
                    ? 'bg-green-900/30 border border-green-700/50'
                    : 'hover:bg-gray-800/50 border border-transparent'
                }`}
              >
                <span
                  className={`w-2.5 h-2.5 rounded-full ${getStatusColor(vm.status)} ${
                    vm.status === 'running' ? 'animate-pulse ring-4 ' + getStatusRing(vm.status) : ''
                  }`}
                />
                <div className="flex-1 min-w-0">
                  <div className="text-sm text-green-400 truncate font-medium">
                    {vm.id}
                  </div>
                  <div className="text-xs text-green-700 truncate">
                    {vm.ip !== 'N/A' ? vm.ip : vm.status}
                  </div>
                </div>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
