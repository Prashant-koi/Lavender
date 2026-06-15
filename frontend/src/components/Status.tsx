import { SEVERITY_LABEL } from '../data/catalog'
import type { AlertStatus, Severity } from '../types/domain'

export function SevDot({ severity, pulse = false }: { severity: Severity; pulse?: boolean }) {
  return (
    <span className="sev">
      <span className={`sev-dot${pulse ? ' pulse' : ''}`} style={{ '--c': `var(--sev-${severity})`, '--ring': `color-mix(in oklab, var(--sev-${severity}) 55%, transparent)` } as React.CSSProperties} title={SEVERITY_LABEL[severity]} />
    </span>
  )
}

export function WorkflowBadge({ status }: { status: AlertStatus }) {
  return <span className="badge" style={{ '--c': `var(--wf-${status})` } as React.CSSProperties}>{status}</span>
}
