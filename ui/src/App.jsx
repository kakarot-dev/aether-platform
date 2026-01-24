import { useState, useEffect } from 'react'
import { TelemetryProvider } from './context/TelemetryContext'
import Header from './components/Header'
import DeployModal from './components/DeployModal'
import SnapshotsView from './components/SnapshotsView'
import MainStatsOverview from './components/MainStatsOverview'
import DashboardLayout from './components/DashboardLayout'

function AppContent() {
  const [vms, setVms] = useState([])
  const [showDeploy, setShowDeploy] = useState(false)
  const [systemInfo, setSystemInfo] = useState(null)
  const [activeTab, setActiveTab] = useState('instances')
  const [snapshots, setSnapshots] = useState([])
  const [actionInProgress, setActionInProgress] = useState({})

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

  // Fetch snapshots
  const fetchSnapshots = async () => {
    try {
      const res = await fetch('/api/snapshots')
      const data = await res.json()
      setSnapshots(data)
    } catch (e) {
      console.error('Failed to fetch snapshots:', e)
    }
  }

  // Helper to set action in progress and auto-clear after 3 seconds
  const setAction = (vmId, action) => {
    setActionInProgress(prev => ({ ...prev, [vmId]: action }))
    setTimeout(() => {
      setActionInProgress(prev => {
        const newState = { ...prev }
        delete newState[vmId]
        return newState
      })
    }, 3000)
  }

  // Auto-refresh every 2 seconds (less frequent since we have WebSocket now)
  useEffect(() => {
    fetchVms()
    fetchSystemInfo()
    fetchSnapshots()
    const interval = setInterval(() => {
      fetchVms()
      if (activeTab === 'snapshots') {
        fetchSnapshots()
      }
    }, 2000)
    return () => clearInterval(interval)
  }, [activeTab])

  // Deploy VM
  const handleDeploy = async (vmId) => {
    try {
      await fetch('/api/deploy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vm_id: vmId })
      })
      setShowDeploy(false)
      fetchVms()
    } catch (e) {
      console.error('Failed to deploy VM:', e)
    }
  }

  // Stop VM
  const handleStop = async (id) => {
    setAction(id, 'stopping')

    // Optimistic update - mark as stopped immediately
    setVms(prevVms => prevVms.map(vm =>
      vm.id === id ? { ...vm, status: 'stopped', ip: 'N/A' } : vm
    ))

    try {
      await fetch('/api/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vm_id: id })
      })
      fetchVms()
    } catch (e) {
      console.error('Failed to stop VM:', e)
      fetchVms()
    }
  }

  // Delete VM
  const handleDelete = async (id) => {
    if (!confirm(`Delete VM "${id}" from database? This cannot be undone.`)) {
      return
    }

    setAction(id, 'deleting')

    // Optimistic update - remove from UI immediately
    setVms(prevVms => prevVms.filter(vm => vm.id !== id))

    try {
      await fetch('/api/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vm_id: id })
      })
      fetchVms()
    } catch (e) {
      console.error('Failed to delete VM:', e)
      fetchVms()
    }
  }

  // Create Disk Snapshot
  const handleCreateSnapshot = async (vmId) => {
    const name = prompt('Snapshot name (required):')
    if (!name || !name.trim()) {
      alert('Snapshot name is required')
      return
    }

    const description = prompt('Snapshot description (optional):')

    setAction(vmId, 'snapshotting')

    try {
      const response = await fetch('/api/vms/disk-snapshot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          vm_id: vmId,
          name: name.trim(),
          description: description && description.trim() ? description.trim() : null
        })
      })

      if (response.ok) {
        alert('Disk snapshot created successfully!')
        fetchSnapshots()
      } else {
        const error = await response.text()
        alert(`Failed to create snapshot: ${error}`)
      }
    } catch (e) {
      console.error('Failed to create snapshot:', e)
      alert('Failed to create snapshot')
    }
  }

  // Pause VM
  const handlePause = async (id) => {
    setAction(id, 'pausing')

    // Optimistic update
    setVms(prevVms => prevVms.map(vm =>
      vm.id === id ? { ...vm, status: 'paused' } : vm
    ))

    try {
      await fetch('/api/vms/pause', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vm_id: id })
      })
      fetchVms()
    } catch (e) {
      console.error('Failed to pause VM:', e)
      fetchVms()
    }
  }

  // Resume VM
  const handleResume = async (id) => {
    setAction(id, 'resuming')

    // Optimistic update
    setVms(prevVms => prevVms.map(vm =>
      vm.id === id ? { ...vm, status: 'running' } : vm
    ))

    try {
      await fetch('/api/vms/resume', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vm_id: id })
      })
      fetchVms()
    } catch (e) {
      console.error('Failed to resume VM:', e)
      fetchVms()
    }
  }

  // Navigate to snapshot
  const navigateToSnapshot = (snapshotId) => {
    setActiveTab('snapshots')
    setTimeout(() => {
      const element = document.getElementById(`snapshot-${snapshotId}`)
      if (element) {
        element.scrollIntoView({ behavior: 'smooth', block: 'center' })
        element.classList.add('ring-2', 'ring-purple-500')
        setTimeout(() => {
          element.classList.remove('ring-2', 'ring-purple-500')
        }, 2000)
      }
    }, 100)
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-950 via-black to-gray-900 text-green-400 font-mono p-4 md:p-8">
      <Header onNewInstance={() => setShowDeploy(!showDeploy)} />

      <div className="max-w-7xl mx-auto">
        {/* Tab Navigation */}
        <div className="flex gap-4 border-b border-green-900/30 mb-8">
          <button
            onClick={() => setActiveTab('instances')}
            className={`px-6 py-3 font-semibold transition-all ${
              activeTab === 'instances'
                ? 'text-green-400 border-b-2 border-green-400'
                : 'text-gray-500 hover:text-green-600'
            }`}
          >
            INSTANCES
          </button>
          <button
            onClick={() => setActiveTab('snapshots')}
            className={`px-6 py-3 font-semibold transition-all ${
              activeTab === 'snapshots'
                ? 'text-green-400 border-b-2 border-green-400'
                : 'text-gray-500 hover:text-green-600'
            }`}
          >
            SNAPSHOTS
          </button>
        </div>

        {/* Instances Tab Content */}
        {activeTab === 'instances' && (
          <>
            {/* Deploy Modal */}
            {showDeploy && (
              <DeployModal
                onDeploy={handleDeploy}
                onCancel={() => setShowDeploy(false)}
              />
            )}

            {/* Stats Overview */}
            <MainStatsOverview vms={vms} systemInfo={systemInfo} />

            {/* Three-Panel Dashboard Layout */}
            <DashboardLayout
              vms={vms}
              onStop={handleStop}
              onDelete={handleDelete}
              onPause={handlePause}
              onResume={handleResume}
              onCreateSnapshot={handleCreateSnapshot}
              actionInProgress={actionInProgress}
            />
          </>
        )}

        {/* Snapshots Tab Content */}
        {activeTab === 'snapshots' && (
          <SnapshotsView
            snapshots={snapshots}
            setActiveTab={setActiveTab}
            fetchSnapshots={fetchSnapshots}
          />
        )}

        {/* Footer */}
        <footer className="mt-12 text-center text-green-900 text-xs">
          <div className="mb-2">
            &gt; Firecracker MicroVM Management System
          </div>
          <div>
            Real-time telemetry via WebSocket | Polling: 2s
          </div>
        </footer>
      </div>
    </div>
  )
}

function App() {
  return (
    <TelemetryProvider>
      <AppContent />
    </TelemetryProvider>
  )
}

export default App
