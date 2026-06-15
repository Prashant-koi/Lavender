import { useCallback, useEffect, useMemo, useState } from 'react'
import { fetchAgents, fetchAlerts, subscribeControlPlane, updateAlertStatus } from './controlPlane'
import type { Agent, Alert, AlertStatus } from '../types/domain'

type LoadState = 'loading' | 'ready' | 'error'

export function useControlPlane() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [agents, setAgents] = useState<Agent[]>([])
  const [state, setState] = useState<LoadState>('loading')
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    Promise.all([fetchAlerts(), fetchAgents()])
      .then(([nextAlerts, nextAgents]) => {
        if (!active) return
        setAlerts(nextAlerts)
        setAgents(nextAgents)
        setState('ready')
        setError(null)
      })
      .catch((err: unknown) => {
        if (!active) return
        setState('error')
        setError(err instanceof Error ? err.message : 'Control-plane request failed')
      })
    return () => {
      active = false
    }
  }, [])

  useEffect(() => {
    if (state !== 'ready') return undefined
    return subscribeControlPlane(
      (alert) => setAlerts((prev) => [alert, ...prev.filter((row) => row.alert_id !== alert.alert_id)].slice(0, 200)),
      (agent) => setAgents((prev) => {
        const i = prev.findIndex((row) => row.agent_id === agent.agent_id && row.tenant_id === agent.tenant_id)
        if (i < 0) return [agent, ...prev]
        const next = prev.slice()
        next[i] = agent
        return next
      }),
    )
  }, [state])

  const setAlertStatus = useCallback(async (alertId: string, status: AlertStatus) => {
    const current = alerts.find((alert) => alert.alert_id === alertId)
    if (!current) return
    const updated = await updateAlertStatus(current, status)
    setAlerts((prev) => prev.map((alert) => (alert.alert_id === alertId ? updated : alert)))
  }, [alerts])

  const summary = useMemo(() => {
    const counts = { online: 0, degraded: 0, offline: 0 }
    agents.forEach((agent) => {
      counts[agent.status] += 1
    })
    return counts
  }, [agents])

  return { alerts, agents, state, error, summary, setAlertStatus }
}
