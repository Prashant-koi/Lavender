import type { AlertStatus, Severity } from '../types/domain'

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low']
export const STATUSES: AlertStatus[] = ['open', 'pending', 'resolved', 'dismissed']
export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
}
