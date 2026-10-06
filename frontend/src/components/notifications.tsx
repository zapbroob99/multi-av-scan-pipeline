import { useEffect, useRef, useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Bell, CheckCircle2, HelpCircle } from 'lucide-react'
import { request } from '../lib/api'
import type { components } from '../lib/api.generated'
import { ErrorMessage } from './error-message'
import { HEALTH_ICONS, HEALTH_STATE_LABEL, useHealth } from './health-panel'
import { Timestamp } from './timestamp'
import { Button } from './ui/button'

type Detection = components['schemas']['Detection']

const SOURCE_LABEL: Record<string, string> = { manual: 'Manual', api: 'API', icap: 'ICAP' }
const PROBLEM_STATES = new Set(['warning', 'critical', 'unknown'])

function detectionLink(item: Detection) {
  return item.source === 'manual' ? `/scans/${item.scan_id}` : `/api-ledger/scans/${item.scan_id}`
}

/**
 * Top bar notifications: recorded detections for every operator, plus the health
 * checks that need attention for administrators. Detections can be marked read
 * (greyed out) or cleared (removed from this list, never from history); a health
 * problem stays until the system is healthy again.
 */
export function NotificationBell({ admin, csrf }: { admin: boolean; csrf: string }) {
  const location = useLocation()
  const queries = useQueryClient()
  const [open, setOpen] = useState(false)
  const wrapper = useRef<HTMLDivElement>(null)
  const toggle = useRef<HTMLButtonElement>(null)
  const panel = useRef<HTMLDivElement>(null)
  const feed = useQuery({ queryKey: ['notifications'], queryFn: ({ signal }) => request('/api/ui/v1/notifications', 'get', { signal }),
    retry: false, refetchInterval: 60000, refetchIntervalInBackground: false, refetchOnWindowFocus: false })
  const health = useHealth(60000, admin)
  const act = useMutation({
    mutationFn: ({ action, through }: { action: 'read' | 'clear'; through: number }) => request(
      action === 'read' ? '/api/ui/v1/notifications/read' : '/api/ui/v1/notifications/clear', 'post',
      { csrf, body: { through_scan_id: through } }),
    onSettled: () => queries.invalidateQueries({ queryKey: ['notifications'] }),
  })

  useEffect(() => { setOpen(false) }, [location.pathname])
  useEffect(() => {
    if (!open) return
    panel.current?.focus()
    const outside = (event: MouseEvent) => { if (!wrapper.current?.contains(event.target as Node)) setOpen(false) }
    document.addEventListener('mousedown', outside)
    return () => document.removeEventListener('mousedown', outside)
  }, [open])

  const problems = admin ? health.data?.checks.filter(check => PROBLEM_STATES.has(check.state)) ?? [] : []
  const healthUnreadable = admin && health.isError
  const unread = feed.data?.unread ?? 0
  const count = unread + problems.length + (healthUnreadable ? 1 : 0)
  const tone = unread > 0 || problems.some(check => check.state === 'critical') ? 'critical' : count ? 'warning' : ''
  const countText = `${count}${feed.data?.unread_capped ? '+' : ''}`
  const detections = feed.data?.detections ?? []

  return <div className="notifications" ref={wrapper} onKeyDown={event => {
    if (event.key === 'Escape' && open) { setOpen(false); toggle.current?.focus() }
  }}>
    <Button ref={toggle} variant="secondary" className="icon-button notifications-toggle" aria-expanded={open} aria-controls="notifications-panel"
      aria-label={count ? `Notifications, ${countText} need attention` : 'Notifications'} title="Notifications" onClick={() => setOpen(value => !value)}>
      <Bell size={16} aria-hidden="true" />
      {count > 0 && <span className={`notifications-count notifications-count-${tone}`} aria-hidden="true">{countText}</span>}
    </Button>
    {open && <div id="notifications-panel" ref={panel} className="notifications-panel" role="dialog" aria-label="Notifications" tabIndex={-1}>
      <div className="notifications-head"><h2>Notifications</h2>
        {detections.length > 0 && <div className="notifications-actions">
          {detections.some(item => item.unread) && <Button variant="secondary" disabled={act.isPending}
            onClick={() => act.mutate({ action: 'read', through: detections[0].scan_id })}>Mark as read</Button>}
          <Button variant="secondary" disabled={act.isPending} title="Remove these detections from this list; scan history keeps them"
            onClick={() => act.mutate({ action: 'clear', through: detections[0].scan_id })}>Clear</Button></div>}</div>
      {act.error && <p role="alert" className="error"><ErrorMessage message={act.error.message} /></p>}
      {admin && <section className="notifications-section" aria-label="System">
        <h3>System</h3>
        {health.isPending && <p className="muted notifications-empty">Checking MASP…</p>}
        {healthUnreadable && <div className="notification notification-unknown"><HelpCircle size={16} aria-hidden="true" />
          <div><p className="notification-title"><strong>System health</strong><span>Unknown</span></p>
            <p>The health report could not be read, so the system state is unknown.</p></div></div>}
        {health.data && !problems.length && <p className="notification notification-ok"><CheckCircle2 size={16} aria-hidden="true" />All systems normal.</p>}
        {problems.length > 0 && <ul>{problems.map(check => {
          const Icon = HEALTH_ICONS[check.state]
          return <li key={check.key} className={`notification notification-${check.state}`}><Icon size={16} aria-hidden="true" />
            <div><p className="notification-title"><strong>{check.label}</strong><span>{HEALTH_STATE_LABEL[check.state]}</span></p>
              <p>{check.summary}</p></div>
            {check.link && <Link to={check.link} aria-label={`Open ${check.label}`}>Open</Link>}</li>
        })}</ul>}
      </section>}
      <section className="notifications-section" aria-label="Detections">
        <h3>Detections</h3>
        {feed.isPending && <p className="muted notifications-empty">Loading…</p>}
        {feed.error && <p role="alert" className="error"><ErrorMessage message={feed.error.message} /></p>}
        {feed.data && !detections.length && <p className="muted notifications-empty">{feed.data.cleared
          ? <>No new detections. Earlier ones stay in the <Link to="/dashboard">dashboard</Link> and the <Link to="/api-ledger">API ledger</Link>.</>
          : 'No detections recorded.'}</p>}
        {detections.length > 0 && <ul>{detections.map(item => <li key={item.scan_id}>
          <Link to={detectionLink(item)} className={`notification notification-detection${item.unread ? ' is-unread' : ''}`}>
            <span className="notification-marker" aria-hidden="true" />
            <div><p className="notification-title"><strong>{item.filename || `Scan #${item.scan_id}`}</strong>
              <span>{item.unread ? 'New' : ''}</span></p>
              <p className="notification-meta">{item.verdict === 'critical' ? 'Critical' : 'High'} risk · {SOURCE_LABEL[item.source] ?? item.source}
                {item.client_name ? ` · ${item.client_name}` : ''}{item.archive_member ? ' · archive member' : ''} · <Timestamp value={item.completed_at} /></p></div>
          </Link></li>)}</ul>}
        {feed.data?.unread_capped && <p className="muted notifications-empty">More than {unread} new detections; the newest are listed.</p>}
      </section>
      {admin && <p className="notifications-foot"><Link to="/system/overview">Open system health</Link></p>}
    </div>}
  </div>
}
