import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import type { components } from '../lib/api.generated'
import { formatTimestamp } from '../lib/utils'
import { formatBytes } from '../lib/storage'
import { Button } from '../components/ui/button'
import { Dialog } from '../components/ui/dialog'
import { ErrorMessage } from '../components/error-message'
import { HelpDetails } from '../components/help-details'
import { age } from './intake'
import { Timestamp } from '../components/timestamp'

type Gateway = components['schemas']['IcapGateway']

const EVENT_LABEL: Record<string, string> = {
  rejected: 'Refused source', blocked: 'Blocked upload', fail_action: 'Fail-closed answer', error: 'Scan error', bad_request: 'Malformed request',
  policy_rejected: 'Rejected by profile policy',
}
const COUNTER_LABEL: [string, string][] = [['requests', 'Requests'], ['allowed', 'Allowed'], ['blocked', 'Blocked'],
  ['fail_actions', 'Fail-closed'], ['errors', 'Errors'], ['policy_rejected', 'Rejected by policy'], ['connections_rejected', 'Refused connections']]

function ClientBinding({ gateway }: { gateway: Gateway }) {
  const name = gateway.client_name || gateway.client_key
  const label = <>{name} <small><code>{gateway.client_key}</code></small></>
  if (gateway.binding === 'unresolved') return <>Nothing: <code>{gateway.client_key}</code> does not resolve</>
  return gateway.client_id ? <Link to={`/service-clients/${gateway.client_id}/setup`}>{label}</Link> : label
}

function BindingNotice({ gateway }: { gateway: Gateway }) {
  const setting = 'MASP_ICAP_SERVICE_CLIENT_KEY'
  if (gateway.binding === 'unresolved') return <p className="notice error" role="alert">{gateway.binding_detail} Every request through
    this gateway fails, so {gateway.fail_closed ? 'every upload is blocked' : 'uploads pass unscanned'}. Enable the client and its
    profile, or set <code>{setting}</code> to an enabled client&apos;s key and restart the icap container.</p>
  if (gateway.binding === 'legacy_default') return <p className="notice">Scans from this gateway are filed under the compatibility
    client, not an integration of their own, so they use its profile and appear as {gateway.client_name || 'legacy-default'} in the
    ledger. To use an integration&apos;s client, set <code>{setting}</code> to its key (shown on the client&apos;s Setup tab) and
    restart the icap container; on pilot installs, edit <code>.env.pilot</code> and run <code>install.sh --no-build</code>.</p>
  return null
}

/** Settings the gateway applies on its own; a gateway older than these fields reports none of them. */
function gatewayRules(gateway: Gateway) {
  if (gateway.block_archives == null && gateway.max_bytes == null && gateway.wait_seconds == null) return 'Not reported by this gateway version'
  const archives = gateway.block_archives == null ? 'archives unknown' : gateway.block_archives ? 'refuses archives unless a profile checks them' : 'scans archives as one file'
  const size = gateway.max_bytes == null ? 'size limit unknown' : gateway.max_bytes ? `size limit ${formatBytes(gateway.max_bytes)}` : 'no size limit'
  const wait = gateway.wait_seconds == null ? 'wait unknown' : `waits up to ${gateway.wait_seconds} s`
  return `${archives[0].toUpperCase()}${archives.slice(1)} · ${size} · ${wait}`
}

function GatewayCard({ gateway }: { gateway: Gateway }) {
  return <article className="submission-card" aria-label={`ICAP gateway ${gateway.client_key}`}>
    <div className="delivery-card-heading"><h2>ICAP gateway · {gateway.client_name || gateway.client_key}</h2>
      <span className={`tag tag-dot ${gateway.stale ? 'tag-danger' : 'tag-positive'}`}>{gateway.stale ? 'Not reporting' : 'Reporting'}</span></div>
    {gateway.stale && <p className="notice error" role="alert">No report for {age(gateway.age_seconds)}. A stopped fail-closed gateway blocks every upload; check the icap container.</p>}
    <BindingNotice gateway={gateway} />
    <dl className="report-metadata">
      <dt>Files scans under</dt><dd><ClientBinding gateway={gateway} /></dd>
      <dt>Service</dt><dd><code>{gateway.service_name}</code> on port {gateway.port}</dd>
      <dt>Policy</dt><dd>{gateway.fail_closed ? 'Fail-closed' : 'Fail-open'}{gateway.block_on_review ? ', review blocks' : ''} · allowlist {gateway.allowlist_entries || 'empty (firewall only)'}</dd>
      <dt>Gateway rules</dt><dd>{gatewayRules(gateway)}</dd>
      <dt>Running since</dt><dd><Timestamp value={gateway.started_at} /></dd>
      <dt>Last request</dt><dd>{gateway.last_request_at ? formatTimestamp(gateway.last_request_at) : 'None since start'}</dd>
    </dl>
    <div className="stats-row delivery-counters">{COUNTER_LABEL.map(([key, label]) =>
      <div key={key}><span>{label}</span><strong>{(gateway.counters[key] ?? 0).toLocaleString()}</strong></div>)}</div>
    <h3 className="delivery-subtitle">Recent events</h3>
    {!gateway.events.length ? <p className="muted">Nothing notable since the gateway started. Allowed uploads are only counted.</p> :
      <div className="history-table-wrap" role="region" aria-label={`Recent ICAP events for ${gateway.client_key}`} tabIndex={0}><table className="history-table compact-table">
        <thead><tr><th scope="col">When</th><th scope="col">Event</th><th scope="col">Detail</th></tr></thead>
        <tbody>{gateway.events.map((event, index) => <tr key={`${event.at}-${index}`} className={event.kind === 'blocked' || event.kind === 'policy_rejected' ? '' : 'row-alert'}>
          <td><small><Timestamp value={event.at} /></small></td><td>{EVENT_LABEL[event.kind] ?? event.kind}</td>
          <td className="hash-value">{event.detail}{event.peer && <small>Source {event.peer}</small>}
            {event.scan_id && <small><Link to={`/api-ledger/scans/${event.scan_id}`}>Scan #{event.scan_id}</Link></small>}</td>
        </tr>)}</tbody></table></div>}
  </article>
}

export default function Delivery({ session }: { session: Session }) {
  const client = useQueryClient()
  const [confirm, setConfirm] = useState(false)
  const [receipt, setReceipt] = useState('')
  const view = useQuery({ queryKey: ['delivery'], queryFn: ({ signal }) => request('/api/ui/v1/system/delivery', 'get', { signal }),
    retry: false, gcTime: 0, refetchInterval: 30000, refetchIntervalInBackground: false, refetchOnWindowFocus: false })
  const retry = useMutation({ retry: false, mutationFn: () => request('/api/ui/v1/system/notifications/retry', 'post', { csrf: session.csrf_token }),
    onMutate: () => setReceipt(''),
    onSuccess: result => setReceipt(`${result.rescheduled} notification(s) will be attempted on the next delivery cycle.`),
    onSettled: async () => { setConfirm(false); await client.invalidateQueries({ queryKey: ['delivery'] }); await client.invalidateQueries({ queryKey: ['system-health'] }) } })
  const data = view.data, notes = data?.notifications
  return <section className="page management-page">
    <div className="page-heading"><div><p className="eyebrow">SYSTEM</p><h1>ICAP and SIEM</h1>
      <p className="muted">Upload gateways and outbound detection notifications.</p></div>
      <Button variant="secondary" disabled={view.isFetching} onClick={() => { void view.refetch() }}>Refresh</Button></div>
    <HelpDetails title="Where this information comes from">Each ICAP gateway writes its counters and recent events every 30 seconds;
      a gateway that stops writing is shown as not reporting. Counters restart with the gateway. Notifications are the malware.detected
      events queued for the SIEM webhook; the notification service retries failures with increasing delays.</HelpDetails>
    {view.isPending && <p role="status">Loading delivery state…</p>}
    {view.error && <p role="alert" className="error"><ErrorMessage message={view.error.message || ''} /></p>}
    {receipt && <p role="status" className="callout">{receipt}</p>}
    {retry.error && <p role="alert" className="error"><ErrorMessage message={retry.error.message || ''} /></p>}
    {data && notes && <>
      {!data.gateways.length && <article className="submission-card"><h2>ICAP gateway</h2>
        <p className="muted">No ICAP gateway has reported. Gateways report from this release on; an older gateway, or one that cannot
          reach the database, does not appear here.</p></article>}
      {data.gateways.map(gateway => <GatewayCard key={gateway.key} gateway={gateway} />)}

      <article className="submission-card" aria-label="SIEM notifications">
        <div className="delivery-card-heading"><h2>SIEM notifications</h2>
          <Button variant="secondary" disabled={!notes.retrying || retry.isPending} onClick={() => setConfirm(true)}>Retry failed now</Button></div>
        <dl className="report-metadata">
          <dt>Waiting</dt><dd>{notes.pending}{notes.retrying ? ` (${notes.retrying} failed at least once)` : ''}{notes.delivering ? ` · ${notes.delivering} being sent` : ''}</dd>
          <dt>Oldest waiting</dt><dd>{notes.oldest_pending_at ? formatTimestamp(notes.oldest_pending_at) : 'Nothing waiting'}</dd>
          <dt>Delivered</dt><dd>{notes.delivered.toLocaleString()}{notes.last_delivered_at ? ` · last ${formatTimestamp(notes.last_delivered_at)}` : ''}</dd>
        </dl>
        {notes.failures.length > 0 && <div className="history-table-wrap" role="region" aria-label="Failed notifications" tabIndex={0}><table className="history-table compact-table">
          <thead><tr><th scope="col">Scan</th><th scope="col">Client</th><th scope="col">Last error</th><th scope="col">Next attempt</th></tr></thead>
          <tbody>{notes.failures.map(row => <tr key={row.id} className="row-alert">
            <td><Link to={`/api-ledger/scans/${row.scan_job_id}`}>Scan #{row.scan_job_id}</Link><small>{row.event_type}</small></td>
            <td className="cell-name">{row.client_name || 'Unknown client'}</td>
            <td className="hash-value">{row.last_error || 'No error recorded'}<small>{row.attempt_count} attempt(s)</small></td>
            <td><small><Timestamp value={row.next_attempt_at} /></small></td>
          </tr>)}</tbody></table></div>}
        {!notes.pending && !notes.delivered && <p className="muted">No notification has been produced. Detections on deferred and API scans create them.</p>}
        {notes.pending > 0 && !notes.delivered && !notes.retrying && !notes.delivering && <p className="muted">No delivery has been attempted yet.
          Detections queue notifications whether or not SIEM delivery is deployed; enable the notifications profile with a SIEM webhook, or ignore this if SIEM is not used.</p>}
      </article>
    </>}
    <Dialog open={confirm} onOpenChange={open => { if (!retry.isPending) setConfirm(open) }} title="Retry failed notifications now?"
      description="Failed notifications waiting in backoff are attempted on the next delivery cycle. Delivered notifications are not sent again.">
      <div className="dialog-actions"><Button variant="secondary" disabled={retry.isPending} onClick={() => setConfirm(false)}>Cancel</Button>
        <Button disabled={retry.isPending} onClick={() => retry.mutate()}>{retry.isPending ? 'Scheduling…' : 'Retry now'}</Button></div>
    </Dialog>
  </section>
}
