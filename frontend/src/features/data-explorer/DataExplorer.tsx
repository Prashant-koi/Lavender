import { useMemo, useState } from 'react'
import { fmtClock, fmtInt } from '../../lib/format'
import { Icon } from '../../components/Icon'
import { SevDot, WorkflowBadge } from '../../components/Status'
import type { Alert } from '../../types/domain'

const PAGE_SIZE = 50

export function DataExplorer({ alerts }: { alerts: Alert[] }) {
  const [q, setQ] = useState('')
  const [page, setPage] = useState(0)
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase()
    if (!needle) return alerts
    return alerts.filter((alert) => `${alert.hostname ?? ''} ${alert.agent_id} ${alert.rule} ${alert.event_comm ?? ''}`.toLowerCase().includes(needle))
  }, [alerts, q])
  const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const cur = Math.min(page, pages - 1)
  const rows = filtered.slice(cur * PAGE_SIZE, cur * PAGE_SIZE + PAGE_SIZE)

  return (
    <div className="tabpane data">
      <div className="data-controls">
        <div className="seg-toggle"><button className="on">Alert data</button><button disabled>Event data</button></div>
        <div className="search"><Icon name="search" /><input placeholder="filter host / id / comm..." value={q} onChange={(event) => { setQ(event.target.value); setPage(0) }} spellCheck="false" /></div>
        <div className="spacer" />
        <span className="result-count">{fmtInt(filtered.length)} rows</span>
      </div>
      <div className="gated-banner"><span className="soon">Unavailable</span> Event data requires a control-plane endpoint. This UI will not synthesize EDR telemetry.</div>
      <div className="data-table-wrap">
        <table className="atable">
          <thead><tr><th className="col-sev">Sev</th><th>Alert ID</th><th>Rule</th><th>Agent / Host</th><th className="col-status">Status</th><th className="col-recv">Received</th></tr></thead>
          <tbody>
            {rows.map((alert) => (
              <tr key={alert.alert_id}>
                <td className="col-sev"><SevDot severity={alert.severity} /></td>
                <td className="cell-mono muted">{alert.alert_id.slice(0, 13)}...</td>
                <td className="cell-rule">{alert.rule}</td>
                <td className="cell-host">{alert.hostname}<span className="aid">{alert.agent_id}</span></td>
                <td className="col-status"><WorkflowBadge status={alert.status} /></td>
                <td className="col-recv cell-mono muted">{fmtClock(alert.received_at_unix_ms)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && <div className="empty">No alert rows match the current query.</div>}
      </div>
      <div className="pager">
        <span className="pager-info mono">{filtered.length === 0 ? '0' : `${cur * PAGE_SIZE + 1}-${Math.min(filtered.length, cur * PAGE_SIZE + PAGE_SIZE)}`} of {fmtInt(filtered.length)}</span>
        <div className="spacer" />
        <button className="pg-btn" disabled={cur === 0} onClick={() => setPage(0)}>first</button>
        <button className="pg-btn" disabled={cur === 0} onClick={() => setPage(cur - 1)}>prev</button>
        <span className="pager-info mono">page {cur + 1} / {pages}</span>
        <button className="pg-btn" disabled={cur >= pages - 1} onClick={() => setPage(cur + 1)}>next</button>
        <button className="pg-btn" disabled={cur >= pages - 1} onClick={() => setPage(pages - 1)}>last</button>
      </div>
    </div>
  )
}
