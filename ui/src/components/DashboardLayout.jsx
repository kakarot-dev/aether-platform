import { useState } from 'react'
import VmListCompact from './VmListCompact'
import VmDetailPanel from './VmDetailPanel'
import LogsPanel from './LogsPanel'

export default function DashboardLayout({
  vms,
  onStop,
  onDelete,
  onPause,
  onResume,
  onCreateSnapshot,
  actionInProgress
}) {
  const [selectedVmId, setSelectedVmId] = useState(null)
  const [showLogs, setShowLogs] = useState(false)

  const selectedVm = vms.find(vm => vm.id === selectedVmId)

  // Auto-select first VM if none selected and VMs exist
  if (!selectedVmId && vms.length > 0 && !selectedVm) {
    setSelectedVmId(vms[0].id)
  }

  // Clear selection if selected VM no longer exists
  if (selectedVmId && !selectedVm && vms.length > 0) {
    setSelectedVmId(vms[0].id)
  }

  const handleShowLogs = (vmId) => {
    setShowLogs(true)
  }

  const handleCloseLogs = () => {
    setShowLogs(false)
  }

  return (
    <div className="flex gap-4 h-[calc(100vh-280px)] min-h-[500px]">
      {/* Left Panel - VM List (always visible) */}
      <div className="w-56 flex-shrink-0 bg-gray-900/40 border border-green-900/30 rounded-lg overflow-hidden">
        <VmListCompact
          vms={vms}
          selectedVmId={selectedVmId}
          onSelectVm={setSelectedVmId}
        />
      </div>

      {/* Middle Panel - Changes based on showLogs state */}
      <div className="flex-1 bg-gray-900/40 border border-green-900/30 rounded-lg overflow-hidden">
        {showLogs && selectedVmId ? (
          <LogsPanel vmId={selectedVmId} onClose={handleCloseLogs} />
        ) : (
          <VmDetailPanel
            vm={selectedVm}
            onStop={onStop}
            onDelete={onDelete}
            onPause={onPause}
            onResume={onResume}
            onCreateSnapshot={onCreateSnapshot}
            onShowLogs={handleShowLogs}
            actionInProgress={selectedVmId ? actionInProgress[selectedVmId] : null}
          />
        )}
      </div>

      {/* Right Panel - VM Details when logs are showing */}
      {showLogs && selectedVm && (
        <div className="w-80 flex-shrink-0 bg-gray-900/40 border border-green-900/30 rounded-lg overflow-hidden">
          <VmDetailPanel
            vm={selectedVm}
            onStop={onStop}
            onDelete={onDelete}
            onPause={onPause}
            onResume={onResume}
            onCreateSnapshot={onCreateSnapshot}
            onShowLogs={handleShowLogs}
            actionInProgress={selectedVmId ? actionInProgress[selectedVmId] : null}
            compact={true}
          />
        </div>
      )}
    </div>
  )
}
