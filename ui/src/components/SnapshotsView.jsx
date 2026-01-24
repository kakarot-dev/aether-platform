import { useState } from 'react'

export default function SnapshotsView({ snapshots, setActiveTab, fetchSnapshots }) {
  const [spawning, setSpawning] = useState(null)
  const [deleting, setDeleting] = useState(null)

  const handleSpawn = async (snapshotId) => {
    const newVmId = prompt('Enter new VM ID for spawned instance:')
    if (!newVmId || !newVmId.trim()) return

    setSpawning(snapshotId)
    try {
      const response = await fetch('/api/vms/restore-disk', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          snapshot_id: snapshotId,
          new_vm_id: newVmId.trim()
        })
      })

      if (response.ok) {
        alert('VM spawned from snapshot successfully!')
        setActiveTab('instances')
      } else {
        const error = await response.text()
        alert(`Failed to spawn VM: ${error}`)
      }
    } catch (e) {
      console.error('Failed to spawn VM:', e)
      alert('Failed to spawn VM')
    } finally {
      setSpawning(null)
    }
  }

  const handleDeleteSnapshot = async (snapshotId) => {
    if (!confirm('Delete this snapshot? This cannot be undone.')) return

    setDeleting(snapshotId)
    try {
      const response = await fetch('/api/snapshots/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ snapshot_id: snapshotId })
      })

      if (response.ok) {
        alert('Snapshot deleted successfully!')
        fetchSnapshots()
      } else {
        const error = await response.text()
        alert(`Failed to delete snapshot: ${error}`)
      }
    } catch (e) {
      console.error('Failed to delete snapshot:', e)
      alert('Failed to delete snapshot')
    } finally {
      setDeleting(null)
    }
  }

  return (
    <div className="space-y-4">
      <h2 className="text-2xl font-bold text-green-400 mb-4">SNAPSHOTS</h2>

      {snapshots.length === 0 ? (
        <div className="text-center py-12 text-gray-500">
          <div className="text-6xl mb-4">📸</div>
          <div className="text-xl">No snapshots yet</div>
          <div className="text-sm mt-2">Create one from a running VM</div>
        </div>
      ) : (
        snapshots.map(snapshot => (
          <div
            key={snapshot.id}
            id={`snapshot-${snapshot.id}`}
            className="p-6 bg-gradient-to-r from-gray-900/40 to-gray-950/40 border border-green-900/30 rounded-lg transition-all duration-200"
          >
            {/* Snapshot Name/Title */}
            <div className="mb-4">
              <h3 className="text-lg font-bold text-purple-400">
                📸 {snapshot.name}
              </h3>
              <div className="text-xs text-gray-500 mt-1">
                Source: {snapshot.vm_id}
                {snapshot.source_vm_status && ` (${snapshot.source_vm_status})`}
              </div>
              {snapshot.description && (
                <div className="text-sm text-gray-400 mt-2">
                  {snapshot.description}
                </div>
              )}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Column 2: Created */}
              <div>
                <div className="text-xs text-green-700 mb-2">CREATED</div>
                <div className="text-green-400">
                  {new Date(snapshot.created_at).toLocaleString()}
                </div>
              </div>

              {/* Column 3: Size */}
              <div>
                <div className="text-xs text-green-700 mb-2">SIZE</div>
                <div className="text-green-400">{snapshot.size_mb} MB</div>
              </div>

              {/* Column 4: Actions */}
              <div className="flex items-center justify-end gap-2">
                <button
                  onClick={() => handleSpawn(snapshot.id)}
                  disabled={spawning === snapshot.id || deleting === snapshot.id}
                  className="px-4 py-2 border border-green-700 text-green-400 rounded hover:bg-green-900/20 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {spawning === snapshot.id ? 'SPAWNING...' : '🚀 SPAWN'}
                </button>
                <button
                  onClick={() => handleDeleteSnapshot(snapshot.id)}
                  disabled={spawning === snapshot.id || deleting === snapshot.id}
                  className="px-4 py-2 border border-red-700 text-red-400 rounded hover:bg-red-900/20 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {deleting === snapshot.id ? 'DELETING...' : '🗑 DELETE'}
                </button>
              </div>
            </div>
          </div>
        ))
      )}
    </div>
  )
}
