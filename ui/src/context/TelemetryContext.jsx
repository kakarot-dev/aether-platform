import { createContext, useContext, useReducer, useEffect } from 'react'
import { useWebSocket } from '../hooks/useWebSocket'

const TelemetryContext = createContext(null)

const MAX_METRICS_HISTORY = 60  // 60 data points (30 seconds at 500ms intervals)
const MAX_LOG_LINES = 500

const initialState = {
  connected: false,
  metrics: {},  // { vmId: [{ cpu, memory, ts }, ...] }
  logs: {},     // { vmId: [{ line, ts }, ...] }
}

function telemetryReducer(state, action) {
  switch (action.type) {
    case 'SET_CONNECTED':
      return { ...state, connected: action.payload }

    case 'ADD_METRICS': {
      const { vm_id, cpu, memory, memory_bytes, memory_limit_bytes, throttle, ts } = action.payload
      const existing = state.metrics[vm_id] || []
      const updated = [
        ...existing,
        { cpu, memory, memory_bytes, memory_limit_bytes, throttle, ts }
      ].slice(-MAX_METRICS_HISTORY)

      return {
        ...state,
        metrics: {
          ...state.metrics,
          [vm_id]: updated
        }
      }
    }

    case 'ADD_LOG': {
      const { vm_id, line, ts } = action.payload
      const existing = state.logs[vm_id] || []
      const updated = [...existing, { line, ts }].slice(-MAX_LOG_LINES)

      return {
        ...state,
        logs: {
          ...state.logs,
          [vm_id]: updated
        }
      }
    }

    case 'CLEAR_VM': {
      const vmId = action.payload
      const newMetrics = { ...state.metrics }
      const newLogs = { ...state.logs }
      delete newMetrics[vmId]
      delete newLogs[vmId]

      return {
        ...state,
        metrics: newMetrics,
        logs: newLogs
      }
    }

    default:
      return state
  }
}

export function TelemetryProvider({ children }) {
  const [state, dispatch] = useReducer(telemetryReducer, initialState)
  const { connected, lastMessage } = useWebSocket()

  // Update connection status
  useEffect(() => {
    dispatch({ type: 'SET_CONNECTED', payload: connected })
  }, [connected])

  // Process incoming messages
  useEffect(() => {
    if (!lastMessage) return

    if (lastMessage.type === 'metrics') {
      dispatch({ type: 'ADD_METRICS', payload: lastMessage })
    } else if (lastMessage.type === 'log') {
      dispatch({ type: 'ADD_LOG', payload: lastMessage })
    }
  }, [lastMessage])

  const clearVm = (vmId) => {
    dispatch({ type: 'CLEAR_VM', payload: vmId })
  }

  const getMetrics = (vmId) => state.metrics[vmId] || []
  const getLogs = (vmId) => state.logs[vmId] || []
  const getLatestMetrics = (vmId) => {
    const metrics = state.metrics[vmId]
    return metrics?.[metrics.length - 1] || null
  }

  return (
    <TelemetryContext.Provider value={{
      connected: state.connected,
      metrics: state.metrics,
      logs: state.logs,
      getMetrics,
      getLogs,
      getLatestMetrics,
      clearVm
    }}>
      {children}
    </TelemetryContext.Provider>
  )
}

export function useTelemetry() {
  const context = useContext(TelemetryContext)
  if (!context) {
    throw new Error('useTelemetry must be used within a TelemetryProvider')
  }
  return context
}
