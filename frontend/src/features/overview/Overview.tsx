import { useMemo, useState } from 'react'
import { Area, AreaChart, CartesianGrid, Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { SevDot, WorkflowBadge } from '../../components/Status'
import { fmtClock, fmtInt, fmtRel } from '../../lib/format'
import type { Agent, Alert } from '../../types/domain'

type RangeKey = '1h' | '24h' | '7d'

// bucket size is driven by range readability + alert sparsity, never finer than
// 1 min (below that it is pipeline-latency noise, not signal).
const RANGES: Record<RangeKey, { ms: number; bucket: number; label: string }> = {
  '1h': { ms: 3_600_000, bucket: 60_000, label: '1 min' },
  '24h': { ms: 86_400_000, bucket: 3_600_000, label: '1 hour' },
  '7d': { ms: 604_800_000, bucket: 21_600_000, label: '6 hour' },
}

const RECENT_LIMIT = 20
const PALETTE = ['#7c6fd6', '#2563eb', '#dc2626', '#d97706', '#16a34a', '#6557c4', '#a78bfa', '#71717a']
const TIP_STYLE = { fontFamily: 'var(--font-mono)', fontSize: 11, border: '1px solid var(--line-strong)', borderRadius: 4, padding: '6px 9px' } as const

// "T1059 [Unexpected shell spawn]" -> "T1059" so related rules collapse together
function technique(rule: string): string {
  const match = rule.match(/^(T\d+(?:\.\d+)?)/)
  return match ? match[1] : rule
}

const pct = (value: number, total: number) => (total ? Math.round((value / total) * 100) : 0)
const fmtTick = (ms: number, range: RangeKey) => (range === '7d' ? new Date(ms).toISOString().slice(5, 10) : fmtClock(ms))

function Kpi({ label, value, tone }: { label: string; value: number | string; tone?: 'red' | 'amber' }) {
  return (
    <div className="kpi">
      <div className={`kpi-num${tone ? ` ${tone}` : ''}`}>{typeof value === 'number' ? fmtInt(value) : value}</div>
      <div className="kpi-lbl">{label}</div>
    </div>
  )
}

export function Overview({ alerts, agents, onViewAll }: { alerts: Alert[]; agents: Agent[]; onViewAll: () => void }) {
  const [range, setRange] = useState<RangeKey>('24h')
  const cfg = RANGES[range]

  const series = useMemo(() => {
    const now = Date.now()
    const start = now - cfg.ms
    const n = Math.ceil(cfg.ms / cfg.bucket)
    const buckets = Array.from({ length: n }, (_, i) => ({ t: start + i * cfg.bucket, count: 0 }))
    for (const alert of alerts) {
      const ts = alert.received_at_unix_ms
      if (ts < start || ts > now) continue
      buckets[Math.min(n - 1, Math.floor((ts - start) / cfg.bucket))].count += 1
    }
    return buckets
  }, [alerts, cfg])

  const byType = useMemo(() => {
    const counts = new Map<string, { name: string; value: number; full: string }>()
    for (const alert of alerts) {
      const key = technique(alert.rule)
      const cur = counts.get(key)
      if (cur) cur.value += 1
      else counts.set(key, { name: key, value: 1, full: alert.rule })
    }
    return Array.from(counts.values()).sort((a, b) => b.value - a.value)
  }, [alerts])

  const recent = useMemo(
    () => [...alerts].sort((a, b) => b.received_at_unix_ms - a.received_at_unix_ms).slice(0, RECENT_LIMIT),
    [alerts],
  )

  const now = Date.now()
  const total = alerts.length
  const openCount = alerts.filter((alert) => alert.status === 'open').length
  const critHigh = alerts.filter((alert) => alert.severity === 'critical' || alert.severity === 'high').length
  const onlineCount = agents.filter((agent) => agent.status === 'online').length
  const last24 = alerts.filter((alert) => alert.received_at_unix_ms >= now - 86_400_000).length

  return (
    <div className="tabpane overview">
      <div className="ov-scroll">
        <div className="ov-grid">
          <div className="ov-col">
            <div className="kpis">
              <Kpi label="Open alerts" value={openCount} tone="red" />
              <Kpi label="Critical / High" value={critHigh} tone="amber" />
              <Kpi label="Agents online" value={`${onlineCount} / ${agents.length}`} />
              <Kpi label="Alerts (24h)" value={last24} />
            </div>

            <section className="panel tablecard">
              <div className="panel-head">
                <span className="panel-title">Recent alerts</span>
                <button className="panel-link" onClick={onViewAll}>All alerts →</button>
              </div>
              <div className="ov-table-wrap">
                {recent.length === 0 ? (
                  <div className="empty">No alerts</div>
                ) : (
                  <table className="atable">
                    <thead>
                      <tr>
                        <th className="col-sev">Sev</th>
                        <th>Rule</th>
                        <th>Agent / Host</th>
                        <th className="col-status">Status</th>
                        <th className="col-recv">Received</th>
                      </tr>
                    </thead>
                    <tbody>
                      {recent.map((alert) => (
                        <tr key={alert.alert_id} onClick={onViewAll}>
                          <td className="col-sev"><SevDot severity={alert.severity} /></td>
                          <td className="cell-rule">{alert.rule}</td>
                          <td className="cell-host">{alert.hostname}<span className="aid">{alert.agent_id}</span></td>
                          <td className="col-status"><WorkflowBadge status={alert.status} /></td>
                          <td className="col-recv"><span className="rel">{fmtRel(alert.received_at_unix_ms)}</span></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </section>
          </div>

          <div className="ov-col">
            <section className="panel">
              <div className="panel-head">
                <span className="panel-title">Alert rate</span>
                <div className="seg-toggle">
                  {(['1h', '24h', '7d'] as RangeKey[]).map((key) => (
                    <button key={key} className={range === key ? 'on' : ''} onClick={() => setRange(key)}>{key}</button>
                  ))}
                </div>
              </div>
              <div className="chart-meta">{cfg.label} buckets · {fmtInt(total)} alerts loaded</div>
              <div className="chart-box">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={series} margin={{ top: 8, right: 12, left: -18, bottom: 0 }}>
                    <defs>
                      <linearGradient id="rate" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#7c6fd6" stopOpacity={0.28} />
                        <stop offset="100%" stopColor="#7c6fd6" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke="#e4e4e7" vertical={false} />
                    <XAxis dataKey="t" tickFormatter={(value) => fmtTick(value, range)} stroke="#71717a" fontSize={10} tickLine={false} minTickGap={28} />
                    <YAxis allowDecimals={false} stroke="#71717a" fontSize={10} tickLine={false} width={32} />
                    <Tooltip contentStyle={TIP_STYLE} labelFormatter={(value) => fmtTick(value as number, range)} formatter={(value) => [value as number, 'alerts']} />
                    <Area type="monotone" dataKey="count" stroke="#7c6fd6" strokeWidth={1.6} fill="url(#rate)" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </section>

            <section className="panel">
              <div className="panel-head"><span className="panel-title">Alert types</span></div>
              <div className="chart-meta">by MITRE technique · {byType.length} types</div>
              <div className="chart-box">
                {total === 0 ? (
                  <div className="empty">No alerts</div>
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={byType} dataKey="value" nameKey="name" cx="50%" cy="43%" innerRadius={42} outerRadius={74} paddingAngle={1}>
                        {byType.map((slice, i) => <Cell key={slice.name} fill={PALETTE[i % PALETTE.length]} />)}
                      </Pie>
                      <Tooltip contentStyle={TIP_STYLE} formatter={(value, _name, item) => [`${value as number} (${pct(value as number, total)}%)`, (item.payload as { full: string }).full]} />
                      <Legend layout="horizontal" align="center" verticalAlign="bottom" iconType="circle" wrapperStyle={{ fontSize: 11 }} />
                    </PieChart>
                  </ResponsiveContainer>
                )}
              </div>
            </section>
          </div>
        </div>
      </div>
    </div>
  )
}
