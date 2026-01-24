import { useState } from 'react'

export default function DeployModal({ onDeploy, onCancel }) {
  const [vmIdInput, setVmIdInput] = useState('')
  const [deploying, setDeploying] = useState(false)

  const handleDeploy = async () => {
    const vmId = vmIdInput.trim() || `vm-${Math.random().toString(36).substr(2, 8)}`
    setDeploying(true)

    try {
      await onDeploy(vmId)
      setVmIdInput('')
    } finally {
      setDeploying(false)
    }
  }

  return (
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
          onKeyDown={(e) => e.key === 'Enter' && handleDeploy()}
        />
        <button
          onClick={handleDeploy}
          disabled={deploying}
          className="px-6 py-2 bg-green-700 hover:bg-green-600 text-black font-semibold rounded disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {deploying ? 'DEPLOYING...' : 'DEPLOY'}
        </button>
        <button
          onClick={onCancel}
          className="px-6 py-2 bg-gray-800 hover:bg-gray-700 text-green-400 rounded transition-colors"
        >
          CANCEL
        </button>
      </div>
    </div>
  )
}
