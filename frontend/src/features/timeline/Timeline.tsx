import { useMemo, useState } from 'react'
import { fmtClock } from '../../lib/format'
import { useNow } from '../../lib/useNow'
import type { Agent } from '../../types/domain'

export function Timeline({ agents }: { agents: Agent[] }) {
  const groups = useMemo(() => ['all', ...Array.from(new Set(agents.map((agent) => agent.group ?? 'ungrouped')))], [agents])
  const [group, setGroup] = useState('all')
  const now = useNow()
  const t0 = now - 6 * 3600 * 1000
  const lanes = agents.filter((agent) => group === 'all' || (agent.group ?? 'ungrouped') === group).slice(0, 80)
  const pct = (t: number) => Math.max(0, Math.min(100, ((t - t0) / (now - t0)) * 100))
  const ticks = Array.from({ length: 7 }, (_, i) => t0 + i * 3600 * 1000)

  return (
    <div className="tabpane timeline">
      <div className="data-controls">
        <div className="fgroup"><span className="fgroup-label">Group</span><select className="minisel" value={group} onChange={(event) => setGroup(event.target.value)}>{groups.map((item) => <option key={item} value={item}>{item}</option>)}</select></div>
        <div className="tl-legend"><span><i className="lg-online" /> online</span><span><i className="lg-offline" /> offline</span></div>
        <div className="spacer" />
        <span className="result-count">{lanes.length} lanes</span>
      </div>
      <div className="tl-grid">
        <div className="tl-axis">
          <div className="tl-name axis-corner">last 6h</div>
          <div className="tl-track axis-track">{ticks.map((tick) => <span key={tick} className="tl-tick" style={{ left: `${pct(tick)}%` }}>{fmtClock(tick)}</span>)}</div>
        </div>
        <div className="tl-lanes">
          {lanes.map((agent) => {
            const offlineStart = agent.status === 'offline' ? (agent.offline_since_unix_ms ?? agent.last_seen_unix_ms) : null
            return (
              <div className="tl-row" key={`${agent.tenant_id}-${agent.agent_id}`}>
                <div className="tl-name">{agent.hostname}</div>
                <div className="tl-track">{offlineStart && <span className="tl-down" style={{ left: `${pct(offlineStart)}%`, width: `${100 - pct(offlineStart)}%` }} title={`${agent.hostname} offline since ${fmtClock(offlineStart)}`} />}</div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
