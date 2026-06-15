import { useEffect, useMemo, useRef, useState } from 'react'
import { SEVERITIES, SEVERITY_LABEL, STATUSES } from '../../data/catalog'
import { fmtAbs, fmtRel } from '../../lib/format'
import { Icon } from '../../components/Icon'
import { SevDot, WorkflowBadge } from '../../components/Status'
import type { Agent, Alert, AlertStatus, Severity } from '../../types/domain'

type Filters = {
  severity: Set<Severity>
  status: Set<AlertStatus>
  rule: string
  agent: string
  q: string
}

const emptyFilters = (): Filters => ({ severity: new Set(), status: new Set(), rule: '', agent: '', q: '' })
const QUICK_ACTIONS: Array<{ status: AlertStatus; icon: 'clock' | 'check' | 'x'; title: string }> = [
  { status: 'pending', icon: 'clock', title: 'Acknowledge' },
  { status: 'resolved', icon: 'check', title: 'Resolve' },
  { status: 'dismissed', icon: 'x', title: 'Dismiss' },
]

export function AlertsTab({ alerts, agents, onAction }: {
  alerts: Alert[]
  agents: Agent[]
  onAction: (alertId: string, status: AlertStatus) => void
}) {
  const [filters, setFilters] = useState<Filters>(() => emptyFilters())
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [drawerId, setDrawerId] = useState<string | null>(null)
  const [newIds, setNewIds] = useState(() => new Set<string>())
  const prevTop = useRef(alerts[0]?.alert_id)

  useEffect(() => {
    const top = alerts[0]
    if (!top || top.alert_id === prevTop.current) return undefined
    prevTop.current = top.alert_id
    setNewIds((prev) => new Set(prev).add(top.alert_id))
    const timer = window.setTimeout(() => setNewIds((prev) => {
      const next = new Set(prev)
      next.delete(top.alert_id)
      return next
    }), 7000)
    return () => window.clearTimeout(timer)
  }, [alerts])

  const counts = useMemo(() => {
    const out = { severity: {} as Record<string, number>, status: {} as Record<string, number> }
    alerts.forEach((alert) => {
      out.severity[alert.severity] = (out.severity[alert.severity] || 0) + 1
      out.status[alert.status] = (out.status[alert.status] || 0) + 1
    })
    return out
  }, [alerts])
  const rules = useMemo(() => Array.from(new Set(alerts.map((alert) => alert.rule))).sort(), [alerts])

  const filtered = useMemo(() => {
    const q = filters.q.trim().toLowerCase()
    return alerts.filter((alert) => {
      if (filters.severity.size && !filters.severity.has(alert.severity)) return false
      if (filters.status.size && !filters.status.has(alert.status)) return false
      if (filters.rule && alert.rule !== filters.rule) return false
      if (filters.agent && alert.agent_id !== filters.agent) return false
      if (!q) return true
      return `${alert.rule} ${alert.hostname ?? ''} ${alert.event_comm ?? ''} ${alert.agent_id}`.toLowerCase().includes(q)
    })
  }, [alerts, filters])

  const drawerAlert = drawerId ? alerts.find((alert) => alert.alert_id === drawerId) : null
  const openDetail = (alert: Alert) => {
    setSelectedId(alert.alert_id)
    setDrawerId(alert.alert_id)
  }

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement
      if (target.tagName === 'INPUT' || target.tagName === 'SELECT') return
      if (event.key === 'Escape') {
        setDrawerId(null)
        return
      }
      if (!filtered.length) return
      const idx = filtered.findIndex((alert) => alert.alert_id === selectedId)
      if (event.key === 'ArrowDown' || event.key === 'j') {
        event.preventDefault()
        const next = filtered[Math.min(filtered.length - 1, idx < 0 ? 0 : idx + 1)]
        setSelectedId(next.alert_id)
        if (drawerId) setDrawerId(next.alert_id)
      }
      if (event.key === 'ArrowUp' || event.key === 'k') {
        event.preventDefault()
        const next = filtered[Math.max(0, idx < 0 ? 0 : idx - 1)]
        setSelectedId(next.alert_id)
        if (drawerId) setDrawerId(next.alert_id)
      }
      if (event.key === 'Enter') {
        const current = filtered.find((alert) => alert.alert_id === selectedId)
        if (current) openDetail(current)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [drawerId, filtered, selectedId])

  return (
    <div className="tabpane alerts-pane">
      <Toolbar filters={filters} setFilters={setFilters} counts={counts} agents={agents} rules={rules} shown={filtered.length} total={alerts.length} />
      <div className="alerts">
        <table className="atable">
          <thead><tr><th className="col-sev">Sev</th><th>Rule</th><th>Agent / Host</th><th className="col-pid">PID</th><th className="col-comm">Comm</th><th className="col-status">Status</th><th className="col-recv">Received</th></tr></thead>
          <tbody>
            {filtered.map((alert) => (
              <AlertRow key={alert.alert_id} alert={alert} selected={alert.alert_id === selectedId} isNew={newIds.has(alert.alert_id)} onSelect={openDetail} onAction={onAction} />
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && <div className="empty">No alerts match the current filters.</div>}
      </div>
      <Drawer alert={drawerAlert ?? null} onClose={() => setDrawerId(null)} onStatus={onAction} />
    </div>
  )
}

function Toolbar({ filters, setFilters, counts, agents, rules, shown, total }: {
  filters: Filters
  setFilters: (filters: Filters) => void
  counts: { severity: Record<string, number>; status: Record<string, number> }
  agents: Agent[]
  rules: string[]
  shown: number
  total: number
}) {
  const toggle = (key: 'severity' | 'status', value: Severity | AlertStatus) => {
    const next = new Set(filters[key] as Set<Severity & AlertStatus>)
    if (next.has(value as Severity & AlertStatus)) next.delete(value as Severity & AlertStatus)
    else next.add(value as Severity & AlertStatus)
    setFilters({ ...filters, [key]: next })
  }
  const active = filters.severity.size || filters.status.size || filters.rule || filters.agent || filters.q
  return (
    <div className="toolbar">
      <div className="fgroup">
        <span className="fgroup-label">Sev</span>
        {SEVERITIES.map((severity) => <Chip key={severity} label={severity} color={`var(--sev-${severity})`} count={counts.severity[severity] || 0} active={filters.severity.has(severity)} onClick={() => toggle('severity', severity)} />)}
      </div>
      <div className="sep" />
      <div className="fgroup">
        <span className="fgroup-label">State</span>
        {STATUSES.map((status) => <Chip key={status} label={status} color={`var(--wf-${status})`} count={counts.status[status] || 0} active={filters.status.has(status)} onClick={() => toggle('status', status)} />)}
      </div>
      <div className="sep" />
      <div className="fgroup">
        <select className="minisel" value={filters.rule} onChange={(event) => setFilters({ ...filters, rule: event.target.value })}>
          <option value="">all rules</option>
          {rules.map((rule) => <option key={rule} value={rule}>{rule}</option>)}
        </select>
        <select className="minisel" value={filters.agent} onChange={(event) => setFilters({ ...filters, agent: event.target.value })}>
          <option value="">all hosts</option>
          {agents.map((agent) => <option key={agent.agent_id} value={agent.agent_id}>{agent.hostname}</option>)}
        </select>
      </div>
      <div className="search"><Icon name="search" /><input placeholder="filter rule / host / comm..." value={filters.q} onChange={(event) => setFilters({ ...filters, q: event.target.value })} spellCheck="false" /></div>
      {active ? <button className="btn-clear" onClick={() => setFilters(emptyFilters())}>clear</button> : null}
      <div className="spacer" />
      <span className="result-count">{shown} / {total}</span>
      <div className="live"><span className="dot" />Live</div>
    </div>
  )
}

function Chip({ active, color, label, count, onClick }: { active: boolean; color: string; label: string; count: number; onClick: () => void }) {
  return <button className={`chip${active ? ' active' : ''}`} onClick={onClick} style={{ '--c': color } as React.CSSProperties}><span className="swatch" /><span>{label}</span><span className="count">{count}</span></button>
}

function AlertRow({ alert, selected, isNew, onSelect, onAction }: {
  alert: Alert
  selected: boolean
  isNew: boolean
  onSelect: (alert: Alert) => void
  onAction: (alertId: string, status: AlertStatus) => void
}) {
  const critOpen = alert.severity === 'critical' && alert.status === 'open'
  return (
    <tr className={`${selected ? 'selected ' : ''}${isNew ? 'is-new' : ''}`} onClick={() => onSelect(alert)}>
      <td className="col-sev"><SevDot severity={alert.severity} pulse={critOpen} /></td>
      <td><span className="cell-rule">{alert.rule}</span>{isNew && <span className="newtag">NEW</span>}</td>
      <td><span className="cell-host">{alert.hostname}<span className="aid">{alert.agent_id}</span></span></td>
      <td className="col-pid"><span className="cell-mono">{alert.event_pid ?? '-'}</span></td>
      <td className="col-comm"><span className="cell-mono">{alert.event_comm ?? '-'}</span></td>
      <td className="col-status"><WorkflowBadge status={alert.status} /></td>
      <td className="col-recv cell-recv">
        <span className="rel" title={fmtAbs(alert.received_at_unix_ms)}>{fmtRel(alert.received_at_unix_ms)}</span>
        <span className="row-actions">
          {QUICK_ACTIONS.map((action) => <button key={action.status} className="qa" title={action.title} disabled={alert.status === action.status} onClick={(event) => { event.stopPropagation(); onAction(alert.alert_id, action.status) }}><Icon name={action.icon} /></button>)}
        </span>
      </td>
    </tr>
  )
}

function Drawer({ alert, onClose, onStatus }: { alert: Alert | null; onClose: () => void; onStatus: (alertId: string, status: AlertStatus) => void }) {
  return (
    <>
      <div className={`scrim${alert ? ' show' : ''}`} onClick={onClose} />
      {alert && (
        <div className="drawer" role="dialog" aria-label="Alert detail">
          <div className="drawer-head">
            <div className="dh-main"><div className="dh-rule"><SevDot severity={alert.severity} />{alert.rule}</div><div className="dh-id">{alert.alert_id}</div></div>
            <button className="icon-btn" onClick={onClose} title="Close"><Icon name="close" /></button>
          </div>
          <div className="drawer-body">
            <div className="sevbar"><span className="sev-dot" style={{ '--c': `var(--sev-${alert.severity})` } as React.CSSProperties} /><span className="sev-name">{SEVERITY_LABEL[alert.severity]}</span><span className="dim">severity</span><div className="spacer" /><WorkflowBadge status={alert.status} /></div>
            <div className="detail-text">{alert.detail}</div>
            <FieldGroup title="Host" rows={[['Hostname', alert.hostname ?? '-'], ['Agent ID', alert.agent_id], ['Tenant', alert.tenant_id]]} />
            <FieldGroup title="Process" rows={[['Event type', alert.event_type], ['PID', String(alert.event_pid ?? '-')], ['Comm', alert.event_comm ?? '-']]} />
            <FieldGroup title="Timeline" rows={[['Observed', fmtAbs(alert.observed_at_unix_ms)], ['Received', fmtAbs(alert.received_at_unix_ms)], ['Created', fmtAbs(alert.created_at_unix_ms ?? alert.received_at_unix_ms)], ['Updated', fmtAbs(alert.updated_at_unix_ms ?? alert.received_at_unix_ms)]]} />
            <div className="status-block">
              <div className="section-label">Workflow status</div>
              <div className="seg">{STATUSES.map((status) => <button key={status} className={alert.status === status ? 'on' : ''} onClick={() => onStatus(alert.alert_id, status)}><span className="sdot" />{status}</button>)}</div>
            </div>
          </div>
        </div>
      )}
    </>
  )
}

function FieldGroup({ title, rows }: { title: string; rows: Array<[string, string]> }) {
  return (
    <>
      <div className="section-label">{title}</div>
      <dl className="fields">{rows.map(([label, value]) => <><dt key={`${label}-dt`}>{label}</dt><dd key={`${label}-dd`}>{value}</dd></>)}</dl>
    </>
  )
}
