import VmCard from './VmCard'

export default function VmList({
  vms,
  onStop,
  onDelete,
  onPause,
  onResume,
  onCreateSnapshot,
  onNavigateToSnapshot,
  actionInProgress
}) {
  if (vms.length === 0) {
    return (
      <div className="text-center py-20 text-green-700">
        <div className="text-6xl mb-4">◇</div>
        <div className="text-xl">NO ACTIVE INSTANCES</div>
        <div className="text-sm mt-2">Deploy your first VM to get started</div>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {vms.map((vm) => (
        <VmCard
          key={vm.id}
          vm={vm}
          onStop={onStop}
          onDelete={onDelete}
          onPause={onPause}
          onResume={onResume}
          onCreateSnapshot={onCreateSnapshot}
          onNavigateToSnapshot={onNavigateToSnapshot}
          actionInProgress={actionInProgress[vm.id]}
        />
      ))}
    </div>
  )
}
