import CpuGraph from './CpuGraph'
import { useTelemetry } from '../context/TelemetryContext'

export default function VmDetailPanel({
  vm,
  onStop,
  onDelete,
  onPause,
  onResume,
  onCreateSnapshot,
  onShowLogs,
  actionInProgress,
  compact = false
}) {
  const { getLatestMetrics, connected } = useTelemetry()

  if (!vm) {
    return (
      <div className="h-full flex items-center justify-center text-green-800">
        <div className="text-center">
          <div className="text-4xl mb-4 opacity-30">&#9432;</div>
          <div className="text-sm">Select a VM to view details</div>
        </div>
      </div>
    )
  }

  const liveMetrics = getLatestMetrics(vm.id)
  const stats = liveMetrics || vm.stats

  const getStatusBadge = (status) => {
    switch (status) {
      case 'running':
        return (
          <span className="inline-flex items-center px-2 py-1 bg-emerald-900/30 border border-emerald-700 text-emerald-400 text-xs font-semibold rounded">
            <span className="w-2 h-2 bg-emerald-400 rounded-full mr-2 animate-pulse" />
            RUNNING
            {connected && !compact && <span className="ml-2 text-emerald-600">LIVE</span>}
          </span>
        )
      case 'paused':
        return (
          <span className="inline-flex items-center px-2 py-1 bg-yellow-900/30 border border-yellow-700 text-yellow-400 text-xs font-semibold rounded">
            <span className="w-2 h-2 bg-yellow-400 rounded-full mr-2" />
            PAUSED
          </span>
        )
      default:
        return (
          <span className="inline-flex items-center px-2 py-1 bg-red-900/30 border border-red-700 text-red-400 text-xs font-semibold rounded">
            <span className="w-2 h-2 bg-red-400 rounded-full mr-2" />
            {status?.toUpperCase() || 'STOPPED'}
          </span>
        )
    }
  }

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Header */}
      <div className="px-4 py-3 border-b border-green-900/30 flex items-center justify-between">
        <h2 className={`font-semibold text-green-400 truncate ${compact ? 'text-sm' : 'text-lg'}`}>
          {vm.id}
        </h2>
        {getStatusBadge(vm.status)}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Snapshot Indicator */}
        {vm.created_from_snapshot_id && !compact && (
          <div className="inline-flex items-center gap-2 px-3 py-2 bg-purple-900/20 border border-purple-700/50 rounded text-xs text-purple-400">
            <span>From snapshot: {vm.snapshot_name || 'Unnamed'}</span>
          </div>
        )}

        {/* Details Grid */}
        <div className={`grid gap-3 ${compact ? 'grid-cols-1' : 'grid-cols-2'}`}>
          <div className="bg-gray-900/40 rounded-lg p-3 border border-green-900/20">
            <div className="text-xs text-green-700 mb-1">IP ADDRESS</div>
            <div className="text-green-300 font-mono text-sm">
              {vm.ip === 'N/A' ? (
                vm.status === 'running' || vm.status === 'starting' ? (
                  <span className="text-yellow-600 animate-pulse">Allocating...</span>
                ) : (
                  <span className="text-gray-600">N/A</span>
                )
              ) : (
                vm.ip
              )}
            </div>
          </div>
          <div className="bg-gray-900/40 rounded-lg p-3 border border-green-900/20">
            <div className="text-xs text-green-700 mb-1">INTERFACE</div>
            <div className="text-green-300 font-mono text-sm">{vm.tap}</div>
          </div>
        </div>

        {/* Real-time Graph for running VMs (hide in compact mode) */}
        {vm.status === 'running' && connected && !compact && (
          <div className="bg-gray-900/40 rounded-lg p-4 border border-green-900/20">
            <div className="text-xs text-green-700 mb-3 font-semibold tracking-wider">
              REAL-TIME METRICS
            </div>
            <CpuGraph vmId={vm.id} />
          </div>
        )}

        {/* Compact metrics for right panel */}
        {vm.status === 'running' && stats && compact && (
          <div className="bg-gray-900/40 rounded-lg p-3 border border-green-900/20">
            <div className="space-y-2">
              <div className="flex justify-between items-center">
                <span className="text-xs text-green-700">CPU</span>
                <span className="text-xs text-green-400 font-mono">
                  {stats.cpu_usage_percent?.toFixed(1) || 0}%
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-xs text-green-700">MEM</span>
                <span className="text-xs text-green-400 font-mono">
                  {((stats.memory_usage_bytes || 0) / 1024 / 1024).toFixed(0)} MB
                </span>
              </div>
            </div>
          </div>
        )}

        {/* Fallback stats when not connected (non-compact only) */}
        {vm.status === 'running' && !connected && stats && !compact && (
          <div className="bg-gray-900/40 rounded-lg p-4 border border-green-900/20">
            <div className="text-xs text-green-700 mb-3 font-semibold tracking-wider">
              RESOURCE USAGE (Polling)
            </div>
            <div className="space-y-3">
              <div>
                <div className="flex justify-between items-center mb-1">
                  <span className="text-xs text-green-600">CPU</span>
                  <span className="text-xs text-green-400 font-mono">
                    {stats.cpu_usage_percent?.toFixed(1) || 0}%
                  </span>
                </div>
                <div className="w-full bg-gray-900 rounded-full h-2 overflow-hidden border border-green-900/50">
                  <div
                    className="bg-gradient-to-r from-emerald-600 to-green-500 h-full transition-all duration-300"
                    style={{ width: `${Math.min(stats.cpu_usage_percent || 0, 100)}%` }}
                  />
                </div>
              </div>
              <div>
                <div className="flex justify-between items-center mb-1">
                  <span className="text-xs text-green-600">MEMORY</span>
                  <span className="text-xs text-green-400 font-mono">
                    {((stats.memory_usage_bytes || 0) / 1024 / 1024).toFixed(0)} MB
                  </span>
                </div>
                <div className="w-full bg-gray-900 rounded-full h-2 overflow-hidden border border-green-900/50">
                  <div
                    className="bg-gradient-to-r from-cyan-600 to-blue-500 h-full transition-all duration-300"
                    style={{ width: `${Math.min(stats.memory_usage_percent || 0, 100)}%` }}
                  />
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Actions */}
        <div className="space-y-2">
          <div className="text-xs text-green-700 font-semibold tracking-wider mb-2">
            ACTIONS
          </div>

          {vm.status === 'running' && (
            <div className={`grid gap-2 ${compact ? 'grid-cols-1' : 'grid-cols-2'}`}>
              {!compact && (
                <button
                  onClick={() => onShowLogs(vm.id)}
                  className="px-3 py-2 bg-gray-900/40 hover:bg-gray-800/60 border border-green-900/30 hover:border-green-700 text-green-400 text-sm font-medium rounded transition-all"
                >
                  View Logs
                </button>
              )}
              <button
                onClick={() => onCreateSnapshot(vm.id)}
                disabled={!!actionInProgress}
                className="px-3 py-2 bg-gray-900/40 hover:bg-gray-800/60 border border-green-900/30 hover:border-green-700 text-green-400 text-sm font-medium rounded transition-all disabled:opacity-50"
              >
                {actionInProgress === 'snapshotting' ? 'Creating...' : 'Snapshot'}
              </button>
              <button
                onClick={() => onPause(vm.id)}
                disabled={!!actionInProgress}
                className="px-3 py-2 bg-yellow-900/20 hover:bg-yellow-800/30 border border-yellow-700 hover:border-yellow-500 text-yellow-400 text-sm font-semibold rounded transition-all disabled:opacity-50"
              >
                {actionInProgress === 'pausing' ? 'Pausing...' : 'Pause'}
              </button>
              <button
                onClick={() => onStop(vm.id)}
                disabled={!!actionInProgress}
                className="px-3 py-2 bg-red-900/20 hover:bg-red-800/30 border border-red-700 hover:border-red-500 text-red-400 text-sm font-semibold rounded transition-all disabled:opacity-50"
              >
                {actionInProgress === 'stopping' ? 'Stopping...' : 'Terminate'}
              </button>
            </div>
          )}

          {vm.status === 'paused' && (
            <div className={`grid gap-2 ${compact ? 'grid-cols-1' : 'grid-cols-2'}`}>
              <button
                onClick={() => onResume(vm.id)}
                disabled={!!actionInProgress}
                className="px-3 py-2 bg-green-900/20 hover:bg-green-800/30 border border-green-700 hover:border-green-500 text-green-400 text-sm font-semibold rounded transition-all disabled:opacity-50"
              >
                {actionInProgress === 'resuming' ? 'Resuming...' : 'Resume'}
              </button>
              <button
                onClick={() => onStop(vm.id)}
                disabled={!!actionInProgress}
                className="px-3 py-2 bg-red-900/20 hover:bg-red-800/30 border border-red-700 hover:border-red-500 text-red-400 text-sm font-semibold rounded transition-all disabled:opacity-50"
              >
                {actionInProgress === 'stopping' ? 'Stopping...' : 'Terminate'}
              </button>
            </div>
          )}

          {(vm.status === 'stopped' || vm.status === 'failed' || vm.status === 'crashed') && (
            <button
              onClick={() => onDelete(vm.id)}
              disabled={!!actionInProgress}
              className="w-full px-3 py-2 bg-gray-900/40 hover:bg-gray-800/60 border border-gray-700 hover:border-gray-500 text-gray-400 text-sm font-semibold rounded transition-all disabled:opacity-50"
            >
              {actionInProgress === 'deleting' ? 'Deleting...' : 'Delete'}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
