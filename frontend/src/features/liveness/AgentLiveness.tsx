import { useMemo, useState } from 'react'
import { fmtDur, fmtInt, fmtRel } from '../../lib/format'
import { useNow } from '../../lib/useNow'
import { Icon } from '../../components/Icon'
import type { Agent } from '../../types/domain'

export function AgentLiveness({ agents }: { agents: Agent[] }) {
  const [showRoster, setShowRoster] = useState(false)
  const [q, setQ] = useState('')
  const now = useNow()
  const counts = useMemo(() => {
    const out = { online: 0, degraded: 0, offline: 0 }
    agents.forEach((agent) => { out[agent.status] += 1 })
    return out
  }, [agents])
  const attention = useMemo(() => agents.filter((agent) => agent.status !== 'online').sort((a, b) => a.status.localeCompare(b.status) || a.hostname.localeCompare(b.hostname)), [agents])
  const roster = useMemo(() => {
    const needle = q.trim().toLowerCase()
    const rows = needle ? agents.filter((agent) => `${agent.hostname} ${agent.agent_id} ${agent.group ?? ''}`.toLowerCase().includes(needle)) : agents
    return { total: rows.length, rows: rows.slice(0, 300) }
  }, [agents, q])

  return (
    <div className="tabpane liveness">
      <div className="liveness-hero">
        <div className="hero-online"><div className="hero-num mono">{fmtInt(counts.online)}</div><div className="hero-lbl">agents online</div></div>
        <div className="hero-stats">
          <HeroStat value={counts.degraded} label="degraded" color="var(--agent-degraded)" />
          <HeroStat value={counts.offline} label="offline" color="var(--agent-offline)" />
          <HeroStat value={agents.length} label="total sensors" color="var(--muted)" />
        </div>
      </div>
      <div className="lv-section">
        <div className="lv-section-head"><span className="panel-title">Needs attention</span><span className="meta mono">{attention.length}</span></div>
        {attention.length === 0 ? <div className="all-clear"><span className="ac-dot" /> All sensors reporting. No degraded or offline agents.</div> : <AgentTable agents={attention} attention now={now} />}
      </div>
      <div className="lv-section">
        <button className="roster-toggle" onClick={() => setShowRoster((value) => !value)}><span className={`caret${showRoster ? ' open' : ''}`}>›</span>{showRoster ? 'Hide' : 'View'} full roster<span className="meta mono">{fmtInt(agents.length)} agents</span></button>
        {showRoster && (
          <div className="roster">
            <div className="roster-search"><Icon name="search" /><input placeholder="filter host / agent-id / group..." value={q} onChange={(event) => setQ(event.target.value)} spellCheck="false" /><span className="result-count">{fmtInt(roster.total)} matches</span></div>
            <div className="roster-list"><AgentTable agents={roster.rows} now={now} /></div>
            {roster.total > roster.rows.length && <div className="roster-more">Showing first {roster.rows.length} of {fmtInt(roster.total)}</div>}
          </div>
        )}
      </div>
    </div>
  )
}

function HeroStat({ value, label, color }: { value: number; label: string; color: string }) {
  return <div className="hstat" style={{ '--c': color } as React.CSSProperties}><span className="hn mono">{fmtInt(value)}</span><span className="hl">{label}</span></div>
}

function AgentTable({ agents, attention = false, now }: { agents: Agent[]; attention?: boolean; now: number }) {
  return (
    <table className="atable lvtable">
      <thead><tr><th className="col-sev">State</th><th>Host</th><th>Agent ID</th><th>Group</th><th className="ar">{attention ? 'Since last contact' : 'Last seen'}</th></tr></thead>
      <tbody>
        {agents.map((agent) => (
          <tr key={`${agent.tenant_id}-${agent.agent_id}`}>
            <td className="col-sev"><span className="sev"><span className={`agent-dot${agent.status === 'offline' ? ' offline-blink' : ''}`} style={{ '--c': `var(--agent-${agent.status})` } as React.CSSProperties} /></span></td>
            <td className="cell-host">{agent.hostname}</td>
            <td className="cell-mono muted">{agent.agent_id}</td>
            <td className="cell-mono muted">{agent.group ?? 'ungrouped'}</td>
            <td className="ar cell-mono" style={{ color: `var(--agent-${agent.status})` }}>{agent.status === 'offline' ? `${fmtDur(now - (agent.offline_since_unix_ms ?? agent.last_seen_unix_ms))} offline` : `${fmtRel(agent.last_seen_unix_ms)} ago`}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
