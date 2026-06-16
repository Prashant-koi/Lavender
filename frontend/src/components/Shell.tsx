import { fmtInt } from '../lib/format'
import type { TabId } from '../types/domain'

const TABS: Array<[TabId, string]> = [
  ['overview', 'Overview'],
  ['alerts', 'Alerts'],
  ['liveness', 'Agent Liveness'],
  ['timeline', 'Timeline'],
]

export function TopBar({ tenant, tenants, onTenant, summary }: {
  tenant: string
  tenants: string[]
  onTenant: (tenant: string) => void
  summary: { online: number; degraded: number; offline: number }
}) {
  return (
    <header className="topbar">
      <div className="brand">
        <span className="wordmark"><span className="mark" />Lavender</span>
        <span className="tagline">Endpoint Detection &amp; Response</span>
      </div>
      <div className="spacer" />
      <div className="topbar-right">
        <label className="tenant-sel" title="Active tenant">
          <span className="label">Tenant</span>
          <select value={tenant} onChange={(event) => onTenant(event.target.value)}>
            {tenants.map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
        </label>
        <div className="live-summary" title="Sensor liveness across the fleet">
          <span className="ls online"><i className="d" /><b className="mono">{fmtInt(summary.online)}</b> online</span>
          {summary.degraded > 0 && <span className="ls degraded"><i className="d" /><b className="mono">{summary.degraded}</b> degraded</span>}
          <span className="ls offline"><i className="d" /><b className="mono">{summary.offline}</b> offline</span>
        </div>
      </div>
    </header>
  )
}

export function Sidebar({ active, onChange, openCount }: { active: TabId; onChange: (tab: TabId) => void; openCount: number }) {
  return (
    <nav className="sidebar">
      {TABS.map(([id, label]) => (
        <button key={id} className={`snav-item${active === id ? ' on' : ''}`} onClick={() => onChange(id)}>
          <span>{label}</span>
          {id === 'alerts' && openCount > 0 ? <span className="snav-badge">{openCount}</span> : null}
        </button>
      ))}
    </nav>
  )
}
