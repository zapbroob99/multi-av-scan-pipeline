import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, CheckCircle2, ChevronRight, CircleDashed, HelpCircle, XCircle } from 'lucide-react'
import { request } from '../lib/api'
import type { components } from '../lib/api.generated'
import { ErrorMessage } from './error-message'
import { Button } from './ui/button'
import { Timestamp } from './timestamp'

type Check = components['schemas']['HealthCheck']
type Overall = components['schemas']['HealthReport']['overall']

export const HEALTH_ICONS = { ok: CheckCircle2, warning: AlertTriangle, critical: XCircle, unknown: HelpCircle, inactive: CircleDashed }
export const HEALTH_STATE_LABEL = { ok: 'OK', warning: 'Attention', critical: 'Failing', unknown: 'Unknown', inactive: 'Not in use' }
export const OVERALL_LABEL: Record<Overall, string> = {
  ok: 'All systems normal', warning: 'Needs attention', critical: 'Action required', unknown: 'Status unknown',
}

/** One query shared by the System overview and the notification bell (administrators only). */
export function useHealth(refetchInterval: number | false = 60000, enabled = true) {
  return useQuery({ queryKey: ['system-health'], queryFn: ({ signal }) => request('/api/ui/v1/system/health', 'get', { signal }),
    enabled, retry: false, gcTime: 60000, refetchInterval, refetchIntervalInBackground: false, refetchOnWindowFocus: false })
}

function CheckRow({ check }: { check: Check }) {
  const Icon = HEALTH_ICONS[check.state]
  return <li className={`health-check health-check-${check.state}`}>
    <Icon size={18} aria-hidden="true" className="health-check-icon" />
    <div className="health-check-body">
      <div className="health-check-title"><strong>{check.label}</strong><span className="health-check-state">{HEALTH_STATE_LABEL[check.state]}</span></div>
      <p>{check.summary}</p>
      {check.detail && <p className="health-check-detail">{check.detail}</p>}
    </div>
    {check.link && <Link className="health-check-link" to={check.link} aria-label={`Open ${check.label}`}>Open<ChevronRight size={14} aria-hidden="true" /></Link>}
  </li>
}

export function HealthPanel() {
  const health = useHealth(30000)
  const data = health.data
  const inactive = data?.checks.filter(check => check.state === 'inactive') ?? []
  return <section className="health-panel" aria-label="System health">
    <div className="health-panel-heading">
      <div><h2>Health</h2>{data && <p className={`health-overall health-overall-${data.overall}`}>{OVERALL_LABEL[data.overall]}</p>}</div>
      <Button variant="secondary" disabled={health.isFetching} onClick={() => { void health.refetch() }}>Check again</Button>
    </div>
    {health.isPending && <p role="status">Checking MASP…</p>}
    {health.error && <p role="alert" className="error"><ErrorMessage message={health.error.message || ''} /></p>}
    {data && <>
      {data.waiting_reason && <p className="notice" role="status"><strong>Why scans are waiting:</strong> {data.waiting_reason}</p>}
      <ul className="health-checks">{data.checks.filter(check => check.state !== 'inactive').map(check => <CheckRow key={check.key} check={check} />)}</ul>
      {inactive.length > 0 && <p className="muted health-inactive">Not in use: {inactive.map(check => check.label).join(', ')}.</p>}
      <p className="muted health-generated">Checked <Timestamp value={data.generated_at} />. Refreshes every 30 seconds while open.</p>
    </>}
  </section>
}
