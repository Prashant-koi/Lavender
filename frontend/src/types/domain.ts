export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type AlertStatus = 'open' | 'pending' | 'acknowledged' | 'resolved' | 'dismissed'
export type AgentStatus = 'online' | 'degraded' | 'offline'
export type TabId = 'overview' | 'alerts' | 'liveness' | 'timeline'

export interface Alert {
  id: number
  alert_id: string
  tenant_id: string
  agent_id: string
  hostname?: string
  rule: string
  severity: Severity
  detail: string
  event_type: string
  event_pid?: number | null
  event_comm?: string | null
  observed_at_unix_ms: number
  received_at_unix_ms: number
  created_at_unix_ms?: number
  updated_at_unix_ms?: number
  status: AlertStatus
}

export interface Agent {
  tenant_id: string
  agent_id: string
  hostname: string
  group?: string
  status: AgentStatus
  last_seen_unix_ms: number
  offline_since_unix_ms?: number
}

export interface TelemetryEvent {
  event_id: string
  tenant_id: string
  agent_id: string
  hostname: string
  event_type: string
  pid: number
  comm: string
  observed_at_unix_ms: number
  received_at_unix_ms: number
  path?: string
  argv?: string
  exe?: string
  daddr?: string
  dport?: number
  proto?: string
  module?: string
}

export interface RuleDefinition {
  rule: string
  severity: Severity
  eventType: string
  commands: string[]
  detail: (command: string) => string
}

export interface TimelineInterval {
  s: number
  e: number
  coord?: boolean
}

export interface TimelineLane {
  agent_id: string
  hostname: string
  group: string
  intervals: TimelineInterval[]
}

export interface LivenessTimeline {
  window: { t0: number; t1: number }
  coord: { start: number; end: number; count: number; total: number }
  lanes: TimelineLane[]
}
