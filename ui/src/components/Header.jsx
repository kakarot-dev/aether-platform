import { useTelemetry } from '../context/TelemetryContext'

export default function Header({ onNewInstance }) {
  const { connected } = useTelemetry()

  return (
    <header className="mb-8 border-b border-green-900/30 pb-6">
      <div className="max-w-7xl mx-auto">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-4xl md:text-5xl font-bold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-green-400 to-emerald-600 mb-2">
              AETHER
            </h1>
            <div className="flex items-center gap-4">
              <p className="text-green-600 text-sm tracking-widest">
                &gt; HYPERVISOR CONTROL PLANE v1.0.0
              </p>
              <div className="flex items-center gap-2">
                <span
                  className={`w-2 h-2 rounded-full ${
                    connected ? 'bg-green-400 animate-pulse' : 'bg-red-400'
                  }`}
                />
                <span className="text-xs text-green-700">
                  {connected ? 'LIVE' : 'OFFLINE'}
                </span>
              </div>
            </div>
          </div>
          <button
            onClick={onNewInstance}
            className="px-6 py-3 bg-green-900/20 hover:bg-green-800/30 border border-green-700 hover:border-green-500 text-green-400 font-semibold rounded-lg transition-all duration-200 shadow-lg shadow-green-900/20 hover:shadow-green-700/40"
          >
            + NEW INSTANCE
          </button>
        </div>
      </div>
    </header>
  )
}
