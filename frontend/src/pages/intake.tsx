import { useQuery } from '@tanstack/react-query'
import { request } from '../lib/api'
import { Button } from '../components/ui/button'
import { SectionTabs, SYSTEM_TABS } from '../components/section-tabs'

export function age(seconds: number) {
  if (seconds < 90) return `${seconds} s`
  if (seconds < 90 * 60) return `${Math.round(seconds / 60)} min`
  if (seconds < 48 * 3600) return `${Math.round(seconds / 3600)} h`
  return `${Math.round(seconds / 86400)} d`
}

const when = (epoch: number) => new Date(epoch * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC'

export default function Intake() {
  const view = useQuery({ queryKey: ['intake'], queryFn: ({ signal }) => request('/api/ui/v1/system/intake', 'get', { signal }),
    retry: false, staleTime: 0, gcTime: 0, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })
  const data = view.data, worker = data?.manifest_worker

  return <section className="page management-page">
    <SectionTabs tabs={SYSTEM_TABS} label="System sections" />
    <div className="page-heading"><div><p className="eyebrow">SYSTEM</p><h1>Deferred intake</h1>
      <p className="muted">Storage manifests and deferred submissions before they become scans.</p></div>
      <Button variant="secondary" disabled={view.isFetching} onClick={() => { void view.refetch() }}>Refresh intake</Button></div>
    <p className="callout">A producer that drops manifests receives no delivery or error feedback, so this page is where a stopped worker,
      a growing backlog or a rejected drop becomes visible. It is a point-in-time read: it does not refresh itself, retry or clear anything.</p>
    {view.isPending && <p role="status">Loading intake state…</p>}
    {view.error && <p role="alert" className="error">{view.error.message}</p>}
    {!view.error && data && <>
      <article className="submission-card" aria-label="Manifest worker">
        <h2>Manifest worker</h2>
        {data.manifest_record_invalid && <p className="notice error" role="alert">The recorded worker state is unreadable. Check the manifest intake worker log.</p>}
        {!worker && !data.manifest_record_invalid && <p className="muted">No manifest intake cycle has been recorded. Either manifest intake is not deployed,
          or its worker has never completed a cycle against this database.</p>}
        {worker && <>
          {worker.stale && <p className="notice error" role="alert">Last cycle was {age(worker.age_seconds)} ago. The worker has stopped or is stuck;
            manifests are not being read.</p>}
          {!worker.ok && <p className="notice error" role="alert">The last cycle failed: {worker.error || 'no detail recorded'}</p>}
          <dl className="report-metadata">
            <dt>Last cycle</dt><dd>{when(worker.at)} ({age(worker.age_seconds)} ago){worker.ok ? '' : ' · failed'}</dd>
            <dt>Last cycle result</dt><dd>{worker.accepted} accepted · {worker.duplicates} already known · {worker.rejected} rejected</dd>
            <dt>Watching</dt><dd>Backend <code>{worker.backend_key || 'unset'}</code>, prefix <code>{worker.root_prefix || '(root)'}</code>
              {worker.date_layout ? `, ${worker.lookback_days} dated partition(s) as ${worker.date_layout}` : ', no date partitions'}</dd>
            <dt>Client</dt><dd><code>{worker.client_key || 'unset'}</code></dd>
            <dt>Polling</dt><dd>Every {worker.poll_seconds} s, up to {worker.batch_limit} manifests per cycle</dd>
          </dl>
          <p className="muted">Configuration is what the worker itself reported, not the API process's environment.</p>
        </>}
      </article>

      <article className="submission-card" aria-label="Deferred queue">
        <h2>Deferred queue</h2>
        <dl className="report-metadata">
          <dt>Waiting to be copied</dt><dd>{data.queue.pending}{data.queue.retrying ? ` (${data.queue.retrying} retrying after an error)` : ''}</dd>
          <dt>Being copied</dt><dd>{data.queue.claimed}</dd>
          <dt>Handed to the scan queue</dt><dd>{data.queue.queued}</dd>
          <dt>Oldest waiting</dt><dd>{data.queue.oldest_pending_age_seconds === null ? 'Nothing waiting'
            : `${age(data.queue.oldest_pending_age_seconds)} (since ${data.queue.oldest_pending_at})`}</dd>
        </dl>
        <p className="muted">Covers every deferred submission, from manifests and from the deferred API. Waiting includes submissions in retry backoff.</p>
      </article>

      <article className="submission-card" aria-label="Rejected manifests">
        <h2>Rejected manifests</h2>
        <p className="muted">{data.rejections_total} recorded{data.rejections_total > data.rejections.length ? `, newest ${data.rejections.length} shown` : ''}.
          A rejection clears itself once the same manifest is accepted. The table keeps at most 1000 records.</p>
        {!data.rejections.length && <p className="empty">No manifest is currently rejected.</p>}
        {data.rejections.length > 0 && <div className="history-table-wrap" role="region" aria-label="Rejected manifests table" tabIndex={0}>
          <table className="history-table compact-table"><thead><tr>
            <th scope="col">Manifest</th><th scope="col">Reason</th><th scope="col">Seen</th>
          </tr></thead><tbody>
          {data.rejections.map(row => <tr key={`${row.backend_key}/${row.manifest_object_id}`} className="row-alert">
            <td className="cell-name" title={row.manifest_object_id}><code>{row.manifest_object_id}</code><small>{row.backend_key}</small></td>
            <td className="hash-value">{row.reason}</td>
            <td><small>{row.occurrences}× · last {when(row.last_seen_at)}</small><small>first {when(row.first_seen_at)}</small></td>
          </tr>)}</tbody></table></div>}
      </article>

      <article className="submission-card" aria-label="Failed before scanning">
        <h2>Failed before scanning</h2>
        <p className="muted">Submissions that failed permanently while being copied or verified. They never became scans, so no report shows them.</p>
        {!data.failures.length && <p className="empty">No deferred submission has failed before scanning.</p>}
        {data.failures.length > 0 && <div className="history-table-wrap" role="region" aria-label="Failed submissions table" tabIndex={0}>
          <table className="history-table compact-table"><thead><tr>
            <th scope="col">Submission</th><th scope="col">Client</th><th scope="col">Error</th><th scope="col">Updated</th>
          </tr></thead><tbody>
          {data.failures.map(row => <tr key={row.id}>
            <td className="cell-name" title={row.object_id}>#{row.id} {row.original_filename}<small>{row.backend_key}/{row.object_id} · request {row.client_request_id}</small></td>
            <td className="cell-name">{row.client_name || `#${row.service_client_id}`}</td>
            <td className="hash-value">{row.last_error || 'No error recorded'}<small>{row.attempt_count} attempt(s)</small></td>
            <td><small>{row.updated_at}</small></td>
          </tr>)}</tbody></table></div>}
        {data.failures_truncated && <p className="muted">Only the newest {data.failures.length} failures are shown.</p>}
      </article>
    </>}
  </section>
}
