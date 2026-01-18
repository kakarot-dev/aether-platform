import { useState, useEffect } from 'react'

function App() {
  const [vms, setVms] = useState([])
  const [deploying, setDeploying] = useState(false)
  const [vmIdInput, setVmIdInput] = useState('')
  const [showDeploy, setShowDeploy] = useState(false)
  const [systemInfo, setSystemInfo] = useState(null)

  // Fetch VMs from API
  const fetchVms = async () => {
    try {
      const res = await fetch('/api/vms')
      const data = await res.json()
      setVms(data)
    } catch (e) {
      console.error('Failed to fetch VMs:', e)
    }
  }

  // Fetch system info
  const fetchSystemInfo = async () => {
    try {
      const res = await fetch('/api/system')
      const data = await res.json()
      setSystemInfo(data)
    } catch (e) {
      console.error('Failed to fetch system info:', e)
    }
  }

  // Auto-refresh every 2 seconds
  useEffect(() => {
    fetchVms()
    fetchSystemInfo()
    const interval = setInterval(fetchVms, 2000)
    return () => clearInterval(interval)
  }, [])

  // Deploy VM
  const handleDeploy = async () => {
    const vmId = vmIdInput.trim() || `vm-${Math.random().toString(36).substr(2, 8)}`
    setDeploying(true)

    try {
      await fetch('/api/deploy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vm_id: vmId })
      })
      setVmIdInput('')
      setShowDeploy(false)
      fetchVms()
    } catch (e) {
      console.error('Failed to deploy VM:', e)
    } finally {
      setDeploying(false)
    }
  }

  // Stop VM
  const handleStop = async (id) => {
    try {
      await fetch('/api/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vm_id: id })
      })
      fetchVms()
    } catch (e) {
      console.error('Failed to stop VM:', e)
    }
  }

  // Delete VM
  const handleDelete = async (id) => {
    if (!confirm(`Delete VM "${id}" from database? This cannot be undone.`)) {
      return
    }

    try {
      await fetch('/api/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vm_id: id })
      })
      fetchVms()
    } catch (e) {
      console.error('Failed to delete VM:', e)
    }
  }

  const runningVms = vms.filter(vm => vm.status === 'running').length
  const stoppedVms = vms.filter(vm => vm.status === 'stopped').length

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-950 via-black to-gray-900 text-green-400 font-mono p-4 md:p-8">
      {/* Header */}
      <header className="mb-8 border-b border-green-900/30 pb-6">
        <div className="max-w-7xl mx-auto">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-4xl md:text-5xl font-bold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-green-400 to-emerald-600 mb-2">
                AETHER
              </h1>
              <p className="text-green-600 text-sm tracking-widest">
                &gt; HYPERVISOR CONTROL PLANE v1.0.0
              </p>
            </div>
            <button
              onClick={() => setShowDeploy(!showDeploy)}
              className="px-6 py-3 bg-green-900/20 hover:bg-green-800/30 border border-green-700 hover:border-green-500 text-green-400 font-semibold rounded-lg transition-all duration-200 shadow-lg shadow-green-900/20 hover:shadow-green-700/40"
            >
              + NEW INSTANCE
            </button>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto">
        {/* Deploy Modal */}
        {showDeploy && (
          <div className="mb-6 p-6 bg-gray-900/50 border border-green-900/50 rounded-lg backdrop-blur-sm">
            <h3 className="text-xl font-bold mb-4 text-green-400">Deploy New VM</h3>
            <div className="flex gap-3">
              <input
                type="text"
                value={vmIdInput}
                onChange={(e) => setVmIdInput(e.target.value)}
                placeholder="vm-id (auto-generated if empty)"
                className="flex-1 px-4 py-2 bg-black border border-green-800 text-green-400 rounded focus:outline-none focus:border-green-500 placeholder-green-800"
                disabled={deploying}
              />
              <button
                onClick={handleDeploy}
                disabled={deploying}
                className="px-6 py-2 bg-green-700 hover:bg-green-600 text-black font-semibold rounded disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {deploying ? 'DEPLOYING...' : 'DEPLOY'}
              </button>
              <button
                onClick={() => setShowDeploy(false)}
                className="px-6 py-2 bg-gray-800 hover:bg-gray-700 text-green-400 rounded transition-colors"
              >
                CANCEL
              </button>
            </div>
          </div>
        )}

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
          <div className="p-6 bg-gradient-to-br from-gray-900/80 to-gray-950/80 border border-green-900/30 rounded-lg backdrop-blur-sm">
            <div className="text-green-600 text-sm mb-2">TOTAL INSTANCES</div>
            <div className="text-4xl font-bold text-green-400">{vms.length}</div>
          </div>
          <div className="p-6 bg-gradient-to-br from-gray-900/80 to-gray-950/80 border border-green-900/30 rounded-lg backdrop-blur-sm">
            <div className="text-green-600 text-sm mb-2">RUNNING</div>
            <div className="text-4xl font-bold text-emerald-400">{runningVms}</div>
          </div>
          <div className="p-6 bg-gradient-to-br from-gray-900/80 to-gray-950/80 border border-green-900/30 rounded-lg backdrop-blur-sm">
            <div className="text-green-600 text-sm mb-2">STOPPED</div>
            <div className="text-4xl font-bold text-red-400">{stoppedVms}</div>
          </div>
        </div>

        {/* System Info */}
        {systemInfo && (
          <div className="mb-8 p-5 bg-gradient-to-r from-gray-900/60 to-gray-950/60 border border-green-900/40 rounded-lg backdrop-blur-sm">
            <div className="text-green-500 text-xs font-semibold mb-3 tracking-wider">SYSTEM INFORMATION</div>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-sm">
              <div>
                <div className="text-green-700 text-xs mb-1">HOST IP</div>
                <div className="text-green-300 font-mono">{systemInfo.host_ip}</div>
              </div>
              <div>
                <div className="text-green-700 text-xs mb-1">INTERFACE</div>
                <div className="text-green-300 font-mono">{systemInfo.interface}</div>
              </div>
              <div>
                <div className="text-green-700 text-xs mb-1">BRIDGE IP</div>
                <div className="text-green-300 font-mono">{systemInfo.bridge_ip}</div>
              </div>
              <div>
                <div className="text-green-700 text-xs mb-1">VM SUBNET</div>
                <div className="text-green-300 font-mono">{systemInfo.vm_subnet}</div>
              </div>
            </div>
          </div>
        )}

        {/* VM Grid */}
        <div className="space-y-3">
          {vms.length === 0 ? (
            <div className="text-center py-20 text-green-700">
              <div className="text-6xl mb-4">◇</div>
              <div className="text-xl">NO ACTIVE INSTANCES</div>
              <div className="text-sm mt-2">Deploy your first VM to get started</div>
            </div>
          ) : (
            vms.map((vm) => (
              <div
                key={vm.id}
                className="group p-6 bg-gradient-to-r from-gray-900/40 to-gray-950/40 border border-green-900/30 hover:border-green-700/50 rounded-lg backdrop-blur-sm transition-all duration-200 hover:shadow-lg hover:shadow-green-900/20"
              >
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
                          </span>
                        ) : (
                          <span className="inline-flex items-center px-3 py-1 bg-red-900/30 border border-red-700 text-red-400 text-xs font-semibold rounded">
                            <span className="w-2 h-2 bg-red-400 rounded-full mr-2"></span>
                            STOPPED
                          </span>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="ml-4 flex gap-2">
                    {vm.status === 'running' && (
                      <button
                        onClick={() => handleStop(vm.id)}
                        className="px-4 py-2 bg-red-900/20 hover:bg-red-800/30 border border-red-700 hover:border-red-500 text-red-400 text-sm font-semibold rounded transition-all duration-200"
                      >
                        TERMINATE
                      </button>
                    )}
                    {vm.status === 'stopped' && (
                      <button
                        onClick={() => handleDelete(vm.id)}
                        className="px-4 py-2 bg-gray-900/20 hover:bg-gray-800/30 border border-gray-700 hover:border-gray-500 text-gray-400 text-sm font-semibold rounded transition-all duration-200"
                      >
                        DELETE
                      </button>
                    )}
                  </div>
                </div>

                {/* Resource Stats (only for running VMs) */}
                {vm.status === 'running' && vm.stats && (
                  <div className="mt-4 pt-4 border-t border-green-900/30">
                    <div className="text-xs text-green-700 mb-3 font-semibold tracking-wider">RESOURCE USAGE</div>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      {/* CPU Usage */}
                      <div>
                        <div className="flex justify-between items-center mb-2">
                          <span className="text-xs text-green-600">CPU</span>
                          <span className="text-xs text-green-400 font-mono">{vm.stats.cpu_usage_percent.toFixed(1)}%</span>
                        </div>
                        <div className="w-full bg-gray-900 rounded-full h-2 overflow-hidden border border-green-900/50">
                          <div
                            className="bg-gradient-to-r from-emerald-600 to-green-500 h-full transition-all duration-300"
                            style={{ width: `${Math.min(vm.stats.cpu_usage_percent, 100)}%` }}
                          ></div>
                        </div>
                        <div className="text-xs text-green-800 mt-1">
                          Limit: 20% | Throttled: {vm.stats.throttle_percent.toFixed(0)}%
                        </div>
                      </div>

                      {/* Memory Usage */}
                      <div>
                        <div className="flex justify-between items-center mb-2">
                          <span className="text-xs text-green-600">MEMORY</span>
                          <span className="text-xs text-green-400 font-mono">
                            {(vm.stats.memory_usage_bytes / 1024 / 1024).toFixed(0)} MB / {(vm.stats.memory_limit_bytes / 1024 / 1024).toFixed(0)} MB
                          </span>
                        </div>
                        <div className="w-full bg-gray-900 rounded-full h-2 overflow-hidden border border-green-900/50">
                          <div
                            className="bg-gradient-to-r from-cyan-600 to-blue-500 h-full transition-all duration-300"
                            style={{ width: `${Math.min(vm.stats.memory_usage_percent, 100)}%` }}
                          ></div>
                        </div>
                        <div className="text-xs text-green-800 mt-1">
                          Usage: {vm.stats.memory_usage_percent.toFixed(1)}%
                        </div>
                      </div>

                      {/* Throttle Stats */}
                      <div>
                        <div className="flex justify-between items-center mb-2">
                          <span className="text-xs text-green-600">THROTTLING</span>
                          <span className="text-xs text-green-400 font-mono">
                            {vm.stats.throttled_periods} / {vm.stats.total_periods}
                          </span>
                        </div>
                        <div className="w-full bg-gray-900 rounded-full h-2 overflow-hidden border border-green-900/50">
                          <div
                            className="bg-gradient-to-r from-yellow-600 to-orange-500 h-full transition-all duration-300"
                            style={{ width: `${Math.min(vm.stats.throttle_percent, 100)}%` }}
                          ></div>
                        </div>
                        <div className="text-xs text-green-800 mt-1">
                          {vm.stats.throttle_percent > 50 ? 'Resource Limited' : 'Normal'}
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ))
          )}
        </div>

        {/* Footer */}
        <footer className="mt-12 text-center text-green-900 text-xs">
          <div className="mb-2">
            &gt; Firecracker MicroVM Management System
          </div>
          <div>
            Auto-refresh: 2s | API: /api/vms
          </div>
        </footer>
      </div>
    </div>
  )
}

export default App
