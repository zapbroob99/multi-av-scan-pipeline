import { type FormEvent } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { request } from '../lib/api'
import { Button } from '../components/ui/button'

const OUTCOMES = ['all', 'success', 'failure', 'denied'] as const

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys)
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort()
    .map(key => [key, sortKeys((value as Record<string, unknown>)[key])]))
  return value
}

/** Legacy parity: complete JSON details are indented with sorted keys. A
 * truncated or non-JSON value is shown exactly as recorded, never repaired. */
export function prettyDetails(details: string, truncated: boolean) {
  if (truncated) return details
  try { return JSON.stringify(sortKeys(JSON.parse(details)), null, 2) } catch { return details }
}

export default function Audit() {
  const [params, setParams] = useSearchParams()
  const query = new URLSearchParams(params)
  query.set('limit', '20')
  const events = useQuery({ queryKey: ['audit', query.toString()],
    queryFn: ({ signal }) => request('/api/ui/v1/audit', 'get', { query, signal }),
    retry: false, staleTime: 0, gcTime: 0, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })
  function filter(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget), next = new URLSearchParams()
    for (const key of ['q', 'outcome']) {
      const value = String(form.get(key) || '').trim()
      if (value && value !== 'all') next.set(key, value)
    }
    setParams(next)
  }
  function paginate(before?: number) {
    const next = new URLSearchParams(params)
    if (before) next.set('before', String(before)); else next.delete('before')
    setParams(next)
  }
  return <section className="page management-page"><div className="page-heading"><div><p className="eyebrow">ACCESS &amp; AUDIT</p>
    <h1>Audit trail</h1><p className="muted">Authentication, administrative changes and destructive actions.</p></div>
    <Button variant="secondary" disabled={events.isFetching} onClick={() => { void events.refetch() }}>Refresh audit trail</Button></div>
    <p className="callout">This is not an HTTP access log: routine navigation, scan submission, polling, report reads and health checks are excluded.
      Events are appended after the handled operation and are best effort, so an absent record does not prove an action did not happen.
      The trail cannot be edited or deleted from this console. Source IP is the direct socket peer, not a forwarded client address.</p>
    <form key={params.toString()} onSubmit={filter} className="submission-card" aria-label="Audit filters"><fieldset className="history-filters">
      <label>Actor, action, target or request ID<input name="q" maxLength={200} defaultValue={params.get('q') || ''} /></label>
      <label>Outcome<select name="outcome" defaultValue={params.get('outcome') || 'all'}>
        {OUTCOMES.map(value => <option key={value} value={value}>{value}</option>)}</select></label>
      <Button type="submit" disabled={events.isFetching}>Apply filters</Button>
      <Button type="button" variant="secondary" onClick={() => setParams({})}>Reset filters</Button>
    </fieldset><p className="muted">Search matches the text exactly; <code>%</code> and <code>_</code> are literal characters, not wildcards.</p></form>
    {events.isPending && <p role="status">Loading audit events…</p>}
    {events.error && <p role="alert" className="error">{events.error.message}</p>}
    {!events.error && events.data && <>
      {!events.data.items.length && <p className="empty">No audit events match these filters.</p>}
      {events.data.items.map(event => <article className="submission-card report-engine" key={event.id}>
        <h2>{event.action}</h2>
        <p className="muted">#{event.id} · {event.created_at} · {event.outcome}</p>
        <p>Actor: {event.actor_name || event.actor_id || 'Anonymous'} ({event.actor_type}{event.actor_id ? ` #${event.actor_id}` : ''})</p>
        <p>Target: {event.target_type}{event.target_id ? ` #${event.target_id}` : ''}</p>
        <p className="muted">Source IP: {event.source_ip || 'Not recorded'} · Request ID: {event.request_id}</p>
        <details><summary>Recorded details</summary>
          <div className="technical-panel"><pre tabIndex={0} aria-label={`Audit event ${event.id} details text`}>{prettyDetails(event.details, event.details_truncated)}</pre></div>
          {event.details_truncated && <p className="muted">Details truncated for display.</p>}
        </details>
      </article>)}
      <div className="history-pagination"><Button variant="secondary" disabled={events.isFetching || !params.get('before')} onClick={() => paginate()}>Newest events</Button>
        <Button variant="secondary" disabled={events.isFetching || !events.data.next_before} onClick={() => paginate(events.data!.next_before!)}>Older events</Button></div>
      <p className="muted">Pages are bounded and no total is calculated. Newer events can arrive while you page through older ones.</p>
    </>}
  </section>
}
