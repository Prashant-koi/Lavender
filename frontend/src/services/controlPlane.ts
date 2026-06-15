import type { Agent, Alert, AlertStatus } from '../types/domain'

const REAL_TO_UI_STATUS: Record<string, AlertStatus> = { acknowledged: 'pending' }
const UI_TO_REAL_STATUS: Partial<Record<AlertStatus, string>> = { pending: 'acknowledged' }

function normalizeAlert(alert: Alert): Alert {
  const received = alert.received_at_unix_ms ?? Date.now()
  return {
    ...alert,
    hostname: alert.hostname || alert.agent_id,
    status: REAL_TO_UI_STATUS[alert.status] ?? alert.status,
    observed_at_unix_ms: alert.observed_at_unix_ms ?? received,
    received_at_unix_ms: received,
    created_at_unix_ms: alert.created_at_unix_ms ?? received,
    updated_at_unix_ms: alert.updated_at_unix_ms ?? received,
  }
}

function normalizeAgent(agent: Agent): Agent {
  const group = agent.group || 'ungrouped'
  return { ...agent, group, status: agent.status === 'degraded' ? 'degraded' : agent.status === 'offline' ? 'offline' : 'online' }
}

async function requestJson<T>(input: RequestInfo | URL, init?: RequestInit): Promise<T> {
  const response = await fetch(input, { headers: { Accept: 'application/json', ...init?.headers }, ...init })
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`)
  return response.json() as Promise<T>
}

export async function fetchAlerts(): Promise<Alert[]> {
  const alerts = await requestJson<Alert[]>('/alerts?limit=200')
  return alerts.map(normalizeAlert)
}

export async function fetchAgents(): Promise<Agent[]> {
  const agents = await requestJson<Agent[]>('/agents')
  return agents.map(normalizeAgent)
}

export async function updateAlertStatus(alert: Alert, status: AlertStatus): Promise<Alert> {
  const backendStatus = UI_TO_REAL_STATUS[status] ?? status
  const updated = await requestJson<Alert>(`/alerts/${alert.id}/status`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status: backendStatus }),
  })
  return normalizeAlert(updated)
}

export function subscribeControlPlane(onAlert: (alert: Alert) => void, onAgent: (agent: Agent) => void) {
  const source = new EventSource('/api/stream')
  source.addEventListener('alert', (event) => onAlert(normalizeAlert(JSON.parse(event.data) as Alert)))
  source.addEventListener('host', (event) => onAgent(normalizeAgent(JSON.parse(event.data) as Agent)))
  return () => source.close()
}
