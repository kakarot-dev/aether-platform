import { useState } from 'react'
import CpuGraph from './CpuGraph'
import LogTerminal from './LogTerminal'
import { useTelemetry } from '../context/TelemetryContext'

export default function VmCard({
  vm,
  onStop,
  onDelete,
  onPause,
  onResume,
  onCreateSnapshot,
  onNavigateToSnapshot,
  actionInProgress
}) {
  const [menuOpen, setMenuOpen] = useState(false)
  const [showLogs, setShowLogs] = useState(false)
  const { getLatestMetrics, connected } = useTelemetry()

  // Use real-time metrics if available, fall back to polling stats
  const liveMetrics = getLatestMetrics(vm.id)
  const stats = liveMetrics || vm.stats

  const handleAction = (action) => {
    setMenuOpen(false)
    action()
  }

  return (
    <div className="group p-6 bg-gradient-to-r from-gray-900/40 to-gray-950/40 border border-green-900/30 hover:border-green-700/50 rounded-lg backdrop-blur-sm transition-all duration-200 hover:shadow-lg hover:shadow-green-900/20">
      {/* Snapshot Indicator */}
      {vm.created_from_snapshot_id && (
        <div className="mb-4 inline-flex items-center gap-2 px-3 py-1 bg-purple-900/20 border border-purple-700/50 rounded text-xs text-purple-400">
          <span>📸</span>
          <span>
            {vm.snapshot_name
              ? `From: ${vm.snapshot_name}`
              : 'Spawned from snapshot'}
          </span>
          <button
            onClick={() => onNavigateToSnapshot(vm.created_from_snapshot_id)}
            className="text-purple-300 underline hover:text-purple-100"
          >
            View
          </button>
        </div>
      )}

      <div className="flex items-center justify-between">
        <div className="flex-1 grid grid-cols-1 md:grid-cols-4 gap-4">
          {/* ID */}
          <div>
            <div className="text-xs text-green-700 mb-1">ID</div>
            <div className="text-green-400 font-semibold truncate" title={vm.id}>
              {vm.id}
            </div>
          </div>

          {/* IP */}
          <div>
            <div className="text-xs text-green-700 mb-1">IP ADDRESS</div>
            <div className="text-green-300">
              {vm.ip === 'N/A' ? (
                vm.status === 'running' || vm.status === 'starting' ? (
                  <span className="text-yellow-600 animate-pulse">ALLOCATING...</span>
                ) : (
                  <span className="text-gray-600">N/A</span>
                )
              ) : (
                vm.ip
              )}
            </div>
          </div>

          {/* Interface */}
          <div>
            <div className="text-xs text-green-700 mb-1">INTERFACE</div>
            <div className="text-green-300">{vm.tap}</div>
          </div>

          {/* Status */}
          <div>
            <div className="text-xs text-green-700 mb-1">STATUS</div>
            <div>
              {vm.status === 'running' ? (
                <span className="inline-flex items-center px-3 py-1 bg-emerald-900/30 border border-emerald-700 text-emerald-400 text-xs font-semibold rounded">
                  <span className="w-2 h-2 bg-emerald-400 rounded-full mr-2 animate-pulse"></span>
                  RUNNING
                  {connected && <span className="ml-2 text-emerald-600">LIVE</span>}
                </span>
              ) : vm.status === 'paused' ? (
                <span className="inline-flex items-center px-3 py-1 bg-yellow-900/30 border border-yellow-700 text-yellow-400 text-xs font-semibold rounded">
                  <span className="w-2 h-2 bg-yellow-400 rounded-full mr-2"></span>
                  PAUSED
                </span>
              ) : (
                <span className="inline-flex items-center px-3 py-1 bg-red-900/30 border border-red-700 text-red-400 text-xs font-semibold rounded">
                  <span className="w-2 h-2 bg-red-400 rounded-full mr-2"></span>
                  {vm.status?.toUpperCase() || 'STOPPED'}
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Actions */}
        <div className="ml-4 flex gap-2">
          {vm.status === 'running' && (
            <>
              <button
                onClick={() => setShowLogs(!showLogs)}
                className="px-3 py-2 border border-green-900/30 hover:border-green-700 text-green-400 rounded transition-all duration-200"
                title="Toggle console logs"
              >
                {showLogs ? '📺' : '📺'}
              </button>
              <div className="relative">
                <button
                  onClick={() => setMenuOpen(!menuOpen)}
                  disabled={!!actionInProgress}
                  className="px-3 py-2 border border-green-900/30 hover:border-green-700 text-green-400 rounded transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
                  title="More actions"
                >
                  ⋮
                </button>

                {menuOpen && (
                  <div className="absolute right-0 mt-2 bg-gray-900 border border-green-900/30 rounded shadow-lg z-10 min-w-[200px]">
                    <button
                      onClick={() => handleAction(() => onCreateSnapshot(vm.id))}
                      disabled={!!actionInProgress}
                      className="block w-full px-4 py-2 text-left hover:bg-gray-800 text-green-400 text-sm border-b border-green-900/30 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {actionInProgress === 'snapshotting' ? '💾 Creating...' : '💾 Disk Snapshot'}
                    </button>
                    <button
                      onClick={() => handleAction(() => onStop(vm.id))}
                      disabled={!!actionInProgress}
                      className="block w-full px-4 py-2 text-left hover:bg-gray-800 text-red-400 text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {actionInProgress === 'stopping' ? '🛑 Stopping...' : '🛑 Terminate'}
                    </button>
                  </div>
                )}
              </div>
              <button
                onClick={() => onPause(vm.id)}
                disabled={!!actionInProgress}
                className="px-4 py-2 bg-yellow-900/20 hover:bg-yellow-800/30 border border-yellow-700 hover:border-yellow-500 text-yellow-400 text-sm font-semibold rounded transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {actionInProgress === 'pausing' ? '⏸ PAUSING...' : '⏸ PAUSE'}
              </button>
            </>
          )}
          {vm.status === 'paused' && (
            <>
              <div className="relative">
                <button
                  onClick={() => setMenuOpen(!menuOpen)}
                  disabled={!!actionInProgress}
                  className="px-3 py-2 border border-green-900/30 hover:border-green-700 text-green-400 rounded transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
                  title="More actions"
                >
                  ⋮
                </button>

                {menuOpen && (
                  <div className="absolute right-0 mt-2 bg-gray-900 border border-green-900/30 rounded shadow-lg z-10 min-w-[200px]">
                    <button
                      onClick={() => handleAction(() => onStop(vm.id))}
                      disabled={!!actionInProgress}
                      className="block w-full px-4 py-2 text-left hover:bg-gray-800 text-red-400 text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {actionInProgress === 'stopping' ? '🛑 Stopping...' : '🛑 Terminate'}
                    </button>
                  </div>
                )}
              </div>
              <button
                onClick={() => onResume(vm.id)}
                disabled={!!actionInProgress}
                className="px-4 py-2 bg-green-900/20 hover:bg-green-800/30 border border-green-700 hover:border-green-500 text-green-400 text-sm font-semibold rounded transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {actionInProgress === 'resuming' ? '▶ RESUMING...' : '▶ RESUME'}
              </button>
            </>
          )}
          {(vm.status === 'stopped' || vm.status === 'paused' || vm.status === 'failed' || vm.status === 'crashed') && (
            <button
              onClick={() => onDelete(vm.id)}
              disabled={!!actionInProgress}
              className="px-4 py-2 bg-gray-900/20 hover:bg-gray-800/30 border border-gray-700 hover:border-gray-500 text-gray-400 text-sm font-semibold rounded transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {actionInProgress === 'deleting' ? 'DELETING...' : 'DELETE'}
            </button>
          )}
        </div>
      </div>

      {/* Live Graph for running VMs */}
      {vm.status === 'running' && connected && (
        <div className="mt-4 pt-4 border-t border-green-900/30">
          <div className="text-xs text-green-700 mb-3 font-semibold tracking-wider">REAL-TIME METRICS</div>
          <CpuGraph vmId={vm.id} />
        </div>
      )}

      {/* Fallback stats when not connected */}
      {vm.status === 'running' && !connected && stats && (
        <div className="mt-4 pt-4 border-t border-green-900/30">
          <div className="text-xs text-green-700 mb-3 font-semibold tracking-wider">RESOURCE USAGE (Polling)</div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* CPU Usage */}
            <div>
              <div className="flex justify-between items-center mb-2">
                <span className="text-xs text-green-600">CPU</span>
                <span className="text-xs text-green-400 font-mono">{stats.cpu_usage_percent?.toFixed(1) || 0}%</span>
              </div>
              <div className="w-full bg-gray-900 rounded-full h-2 overflow-hidden border border-green-900/50">
                <div
                  className="bg-gradient-to-r from-emerald-600 to-green-500 h-full transition-all duration-300"
                  style={{ width: `${Math.min(stats.cpu_usage_percent || 0, 100)}%` }}
                ></div>
              </div>
            </div>

            {/* Memory Usage */}
            <div>
              <div className="flex justify-between items-center mb-2">
                <span className="text-xs text-green-600">MEMORY</span>
                <span className="text-xs text-green-400 font-mono">
                  {((stats.memory_usage_bytes || 0) / 1024 / 1024).toFixed(0)} MB
                </span>
              </div>
              <div className="w-full bg-gray-900 rounded-full h-2 overflow-hidden border border-green-900/50">
                <div
                  className="bg-gradient-to-r from-cyan-600 to-blue-500 h-full transition-all duration-300"
                  style={{ width: `${Math.min(stats.memory_usage_percent || 0, 100)}%` }}
                ></div>
              </div>
            </div>

            {/* Throttle Stats */}
            <div>
              <div className="flex justify-between items-center mb-2">
                <span className="text-xs text-green-600">THROTTLING</span>
                <span className="text-xs text-green-400 font-mono">{(stats.throttle_percent || 0).toFixed(0)}%</span>
              </div>
              <div className="w-full bg-gray-900 rounded-full h-2 overflow-hidden border border-green-900/50">
                <div
                  className="bg-gradient-to-r from-yellow-600 to-orange-500 h-full transition-all duration-300"
                  style={{ width: `${Math.min(stats.throttle_percent || 0, 100)}%` }}
                ></div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Log Terminal */}
      {showLogs && vm.status === 'running' && (
        <LogTerminal vmId={vm.id} onClose={() => setShowLogs(false)} />
      )}
    </div>
  )
}
