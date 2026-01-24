import { useEffect, useRef } from 'react'
import { useTelemetry } from '../context/TelemetryContext'

export default function LogsPanel({ vmId, onClose }) {
  const { getLogs } = useTelemetry()
  const logs = getLogs(vmId)
  const containerRef = useRef(null)

  // Auto-scroll to bottom on new logs
  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight
    }
  }, [logs])

  return (
    <div className="h-full flex flex-col bg-black/80">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-green-900/50 bg-gray-900/80">
        <div className="flex items-center gap-3">
          <span className="text-green-500 text-sm font-semibold">CONSOLE</span>
          <span className="text-green-700 text-xs">
            {vmId} ({logs.length} lines)
          </span>
        </div>
        <button
          onClick={onClose}
          className="text-green-700 hover:text-green-400 text-xs px-3 py-1 border border-green-900/50 rounded hover:border-green-700 transition-colors"
        >
          CLOSE
        </button>
      </div>

      {/* Log Content */}
      <div
        ref={containerRef}
        className="flex-1 overflow-y-auto p-4 font-mono text-xs leading-relaxed"
        style={{ scrollBehavior: 'smooth' }}
      >
        {logs.length === 0 ? (
          <div className="text-green-800 italic">
            Waiting for logs...
            <div className="mt-2 text-green-900 text-xs">
              Logs are streamed via WebSocket when the VM is running.
            </div>
          </div>
        ) : (
          logs.map((log, i) => (
            <div key={i} className="text-green-400 whitespace-pre-wrap break-all hover:bg-green-900/10">
              {log.line}
            </div>
          ))
        )}
      </div>

      {/* Status Bar */}
      <div className="px-4 py-2 border-t border-green-900/50 bg-gray-900/80 text-xs text-green-800">
        Log file: /tmp/aether-logs/{vmId}-console.log
      </div>
    </div>
  )
}
