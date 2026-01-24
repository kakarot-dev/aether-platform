import { useEffect, useRef } from 'react'
import { useTelemetry } from '../context/TelemetryContext'

export default function LogTerminal({ vmId, onClose }) {
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
    <div className="mt-4 border border-green-900/50 rounded-lg overflow-hidden">
      <div className="flex items-center justify-between px-3 py-2 bg-gray-900/80 border-b border-green-900/50">
        <div className="flex items-center gap-2">
          <span className="text-green-500 text-xs font-semibold">CONSOLE</span>
          <span className="text-green-700 text-xs">({logs.length} lines)</span>
        </div>
        <button
          onClick={onClose}
          className="text-green-700 hover:text-green-400 text-xs px-2 py-1 border border-green-900/50 rounded hover:border-green-700 transition-colors"
        >
          CLOSE
        </button>
      </div>
      <div
        ref={containerRef}
        className="h-48 overflow-y-auto bg-black p-3 font-mono text-xs leading-relaxed"
        style={{ scrollBehavior: 'smooth' }}
      >
        {logs.length === 0 ? (
          <div className="text-green-800 italic">Waiting for logs...</div>
        ) : (
          logs.map((log, i) => (
            <div key={i} className="text-green-400 whitespace-pre-wrap break-all">
              {log.line}
            </div>
          ))
        )}
      </div>
    </div>
  )
}
