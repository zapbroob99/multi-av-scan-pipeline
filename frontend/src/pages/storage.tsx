import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Suspense } from 'react'
import { Outlet } from 'react-router-dom'
import { request, type Session } from '../lib/api'
import { shortAge } from '../lib/utils'
import { STATE_LABELS, locationPath, type LocationSummary } from '../lib/storage'
import { ErrorMessage } from '../components/error-message'
import { HelpDetails } from '../components/help-details'
import { SectionTabs } from '../components/section-tabs'
import { Button } from '../components/ui/button'
import { Timestamp } from '../components/timestamp'

export const STORAGE_TABS = [
  { to: '/storage', label: 'Locations', end: true },
  { to: '/storage/findings', label: 'Findings' },
]

export function StorageLayout() {
  return <div className="system-layout">
    <SectionTabs tabs={STORAGE_TABS} label="Folder scanning sections" />
    <Suspense fallback={<p role="status">Loading section…</p>}><Outlet /></Suspense>
  </div>
}

export function cycleProblem(location: LocationSummary): string | null {
  if (!location.enabled) return null
  if (location.last_cycle_invalid) return 'The recorded cycle is unreadable.'
  if (!location.last_cycle) return 'No cycle has run for this location yet.'
  if (location.last_cycle.error) return location.last_cycle.error
  if (location.last_cycle.directory_errors) return `${location.last_cycle.directory_errors} director${location.last_cycle.directory_errors === 1 ? 'y' : 'ies'} could not be read; removals are not recorded until a pass reads everything.`
  return null
}

export default function Storage({ session }: { session: Session }) {
  const admin = session.user.role === 'admin'
  const view = useQuery({ queryKey: ['storage-overview'], queryFn: ({ signal }) => request('/api/ui/v1/storage/overview', 'get', { signal }),
    retry: false, staleTime: 0, gcTime: 0, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })
  const data = view.data, worker = data?.worker

  return <section className="page management-page">
    <div className="page-heading"><div><p className="eyebrow">FOLDER SCANNING</p><h1>Protected locations</h1>
      <p className="muted">Storage locations MASP crawls itself, and what it found in them.</p></div>
      <div className="report-actions">
        {admin && <Link className="button button-primary" to="/storage/locations/new">New location</Link>}
        <Button variant="secondary" disabled={view.isFetching} onClick={() => { void view.refetch() }}>Refresh</Button></div></div>
    <p className="callout">This release runs the light tier only: a content-type policy and the institution hash list. Files routed to the
      full tier wait as <strong>Awaiting full scan</strong> until antivirus scanning of protected locations is available. A file that passed the
      type check was <strong>not</strong> scanned by an antivirus engine.</p>
    <HelpDetails title="How folder scanning works">The storage protection worker walks each enabled location in bounded slices, records every file
      in an inventory, and inspects a file once its size and modification time have stopped changing. Nothing on the share is modified: findings are
      reported here and sent to SIEM, never quarantined. This page is a point-in-time read and does not refresh itself.</HelpDetails>
    {view.isPending && <p role="status">Loading protected locations…</p>}
    {view.error && <p role="alert" className="error"><ErrorMessage message={view.error.message || ''} /></p>}
    {!view.error && data && <>
      <article className="submission-card" aria-label="Storage protection worker">
        <h2>Worker</h2>
        {data.worker_record_invalid && <p className="notice error" role="alert">The recorded worker state is unreadable. Check the storage protection worker log.</p>}
        {!worker && !data.worker_record_invalid && <p className="muted">No storage protection worker has reported. Either the storage-protection
          service is not deployed, or it has never completed a sweep against this database.</p>}
        {worker && <>
          {worker.stale && <p className="notice error" role="alert">Last sweep was {shortAge(worker.age_seconds)} ago. The worker has stopped or is stuck;
            locations are not being read.</p>}
          {!worker.ok && <p className="notice error" role="alert">The last sweep failed: {worker.error || 'no detail recorded'}</p>}
          <dl className="report-metadata">
            <dt>Last sweep</dt><dd><Timestamp value={worker.at} /> ({shortAge(worker.age_seconds)} ago)</dd>
            <dt>Locations run</dt><dd>{worker.locations}</dd>
            <dt>Mounted backends</dt><dd>{worker.backends.length ? worker.backends.map(key => <code key={key}>{key} </code>) : 'None'}</dd>
            <dt>Worker</dt><dd><code>{worker.worker_id || 'unknown'}</code></dd>
          </dl>
        </>}
      </article>

      {!data.locations.length && <p className="empty">No protected location exists yet.{admin ? ' Create one to start folder scanning.' : ''}</p>}
      {data.locations.length > 0 && <div className="history-table-wrap" role="region" aria-label="Protected locations" tabIndex={0}>
        <table className="history-table compact-table"><thead><tr>
          <th scope="col">Location</th><th scope="col">Detected</th><th scope="col">Awaiting full scan</th>
          <th scope="col">Type check passed</th><th scope="col">Waiting</th><th scope="col">Unreadable</th><th scope="col">Last cycle</th>
        </tr></thead><tbody>
        {data.locations.map(location => {
          const problem = cycleProblem(location), counts = location.counts
          return <tr key={location.id} className={location.detected_findings || problem ? 'row-alert' : ''}>
            <td className="cell-name"><Link to={`/storage/locations/${location.id}`}>{location.name}</Link>
              <small><code>{locationPath(location)}</code>{location.enabled ? '' : ' · disabled'}</small>
              <small>{location.client.name} · {location.profile.name}</small></td>
            <td>{counts.light_detected.toLocaleString()}<small>{location.detected_findings.toLocaleString()} finding(s)</small></td>
            <td>{counts.full_pending.toLocaleString()}</td>
            <td title={STATE_LABELS.light_passed}>{counts.light_passed.toLocaleString()}</td>
            <td>{(counts.waiting + counts.changed).toLocaleString()}</td>
            <td>{counts.unreadable.toLocaleString()}</td>
            <td>{location.last_cycle ? <small>{shortAge(location.last_cycle.age_seconds)} ago{location.last_cycle.ok ? '' : ' · failed'}</small> : <small>Never</small>}
              {problem && <small className="error">{problem}</small>}
              {location.last_completed_pass && <small>Last complete crawl <Timestamp value={location.last_completed_pass.finished_at} /></small>}</td>
          </tr>
        })}</tbody></table></div>}
      {data.locations_truncated && <p className="muted">Only the first {data.locations.length} locations are shown.</p>}
    </>}
  </section>
}
