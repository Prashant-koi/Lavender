import { useMemo, useState } from 'react'
import { TopBar, Tabs } from './components/Shell'
import { AlertsTab } from './features/alerts/AlertsTab'
import { AgentLiveness } from './features/liveness/AgentLiveness'
import { DataExplorer } from './features/data-explorer/DataExplorer'
import { Timeline } from './features/timeline/Timeline'
import { useControlPlane } from './services/useControlPlane'
import type { TabId } from './types/domain'

function App() {
  const [tab, setTab] = useState<TabId>('alerts')
  const [tenant, setTenant] = useState('')
  const { alerts, agents, state, error, summary, setAlertStatus } = useControlPlane()
  const openCount = useMemo(() => alerts.filter((alert) => alert.status === 'open').length, [alerts])
  const tenants = useMemo(() => Array.from(new Set([...alerts.map((alert) => alert.tenant_id), ...agents.map((agent) => agent.tenant_id)])).filter(Boolean).sort(), [alerts, agents])
  const activeTenant = tenant || tenants[0] || 'unavailable'

  return (
    <div className="app">
      <TopBar tenant={activeTenant} tenants={tenants.length ? tenants : [activeTenant]} onTenant={setTenant} summary={summary} />
      <Tabs active={tab} onChange={setTab} openCount={openCount} />
      <main className="tabview">
        {state === 'loading' && <div className="empty">Connecting to control-plane...</div>}
        {state === 'error' && <div className="empty error-state">Control-plane unavailable: {error}</div>}
        {state === 'ready' && (
          <>
            {tab === 'alerts' && <AlertsTab alerts={alerts} agents={agents} onAction={setAlertStatus} />}
            {tab === 'liveness' && <AgentLiveness agents={agents} />}
            {tab === 'data' && <DataExplorer alerts={alerts} />}
            {tab === 'timeline' && <Timeline agents={agents} />}
          </>
        )}
      </main>
    </div>
  )
}

export default App
