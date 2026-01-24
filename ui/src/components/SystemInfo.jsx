export default function SystemInfo({ systemInfo }) {
  if (!systemInfo) return null

  return (
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
  )
}
