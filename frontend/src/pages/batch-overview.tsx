import { Link, useParams, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { request, type BatchPage, type BatchScan } from '../lib/api'
import { Button } from '../components/ui/button'

const active = (status: string) => ['queued', 'running', 'finalizing'].includes(status)

export function batchPollInterval(afterId: string, page?: BatchPage) {
  return !afterId && page && (active(page.status) || page.items.some(item => active(item.status))) ? 3000 : false
}

function displayTime(value: string) {
  const iso = value.replace(' ', 'T')
  const date = new Date(/(?:Z|[+-]\d\d(?::?\d\d)?)$/.test(iso) ? iso : iso + 'Z')
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function riskText(scan: BatchScan) {
  if (active(scan.status)) return 'Pending'
  if (scan.risk_score === null) return 'Not scored'
  return `${scan.risk_score} / 100 · ${scan.risk_level}`
}

export default function BatchOverview({ automation = false }: { automation?: boolean }) {
  const { batchId = '' } = useParams()
  const [params, setParams] = useSearchParams()
  const afterId = params.get('after_id') || ''
  const afterCreated = params.get('after_created') || ''
  const query = new URLSearchParams({ limit: '20',
    ...(afterId ? { after_id: afterId } : {}), ...(afterCreated ? { after_created: afterCreated } : {}) })
  const valid = /^\d+$/.test(batchId) && Number.isSafeInteger(Number(batchId)) && Number(batchId) > 0
  const batch = useQuery({ queryKey: ['batch-overview', automation, batchId, query.toString()], enabled: valid,
    queryFn: ({ signal }) => request(automation ? '/api/ui/v1/api-ledger/batches/{batch_id}' : '/api/ui/v1/batches/{batch_id}', 'get', {
      params: { batch_id: Number(batchId) }, query, signal,
    }), retry: false, refetchInterval: query => batchPollInterval(afterId, query.state.data),
    refetchIntervalInBackground: false, refetchOnWindowFocus: !afterId,
    refetchOnMount: 'always', gcTime: 60000 })
  const page = batch.error ? undefined : batch.data
  function firstPage() { const next = new URLSearchParams(params); next.delete('after_id'); next.delete('after_created'); setParams(next) }
  if (!valid) return <section className="page"><h1>Invalid batch ID</h1><Link to={automation ? "/api-ledger" : "/dashboard"}>{automation ? "API ledger" : "Dashboard"}</Link></section>
  return <section className="page"><div className="page-heading"><div><p className="eyebrow">{automation ? 'AUTOMATION' : 'MANUAL'} ARCHIVE BATCH #{batchId}</p>
    <h1>Batch overview</h1><p className="muted report-filename">{page?.filename || `Batch #${batchId}`}{page?.filename_truncated ? '…' : ''}</p></div>
    <div className="report-actions"><Link className="button button-secondary" to={automation ? "/api-ledger" : "/dashboard"}>{automation ? "API ledger" : "Dashboard"}</Link>
      <Button variant="secondary" disabled={batch.isFetching} onClick={() => { void batch.refetch() }}>Refresh batch</Button></div></div>
    <p className="callout">This page lists registered {automation ? 'automation scans matching the batch source and client' : 'manual scans'}. Recorded counts and risk may lag active workers and do not prove clean coverage or complete extraction. Open each report for the backend policy decision and required-engine coverage.</p>
    {automation && <p><Link to={`/api-ledger/batches/${batchId}/status-json`}>Batch status JSON</Link> ? <Link to={`/api-ledger/batches/${batchId}/result-json`}>Batch result JSON</Link></p>}
    {batch.isPending && <p className="skeleton" role="status">Loading batch…</p>}
    {batch.error ? <section className="error" role="alert"><p>{batch.error.message}</p>
      {afterId && <Button variant="secondary" onClick={firstPage}>Return to first page</Button>}</section> : page && <>
      <div className="stats-row dashboard-stats" aria-label="Recorded batch counts">
        <div><span>Registered</span><strong>{page.counts.total.toLocaleString()}</strong></div>
        <div><span>Active</span><strong>{(page.counts.queued + page.counts.running).toLocaleString()}</strong></div>
        <div><span>Completed</span><strong>{page.counts.completed.toLocaleString()}</strong></div>
        <div><span>High risk</span><strong>{page.counts.malicious.toLocaleString()}</strong></div>
      </div>
      <p className="muted archive-context">Batch: {page.status} · Mode: {page.archive_mode} · Recorded {displayTime(page.updated_at)} · Failed: {page.counts.failed} · Skipped: {page.counts.skipped}</p>
      {page.items.length === 0 ? <section className="empty"><h2>No registered scans on this page</h2>
        <p>The batch may be empty, the cursor may be beyond its last item, or extraction may not have registered children.</p></section> :
        <div className="history-table-wrap" tabIndex={0} role="region" aria-label="Batch scans"><table className="history-table">
          <thead><tr><th scope="col">Registered sample</th><th scope="col">Role</th><th scope="col">Status</th><th scope="col">Recorded risk</th><th scope="col">Submitted</th></tr></thead>
          <tbody>{page.items.map(scan => <tr key={scan.id}><td><Link className="sample-link" to={`${automation ? '/api-ledger' : ''}/scans/${scan.id}`}>{scan.path}{scan.path_truncated ? '…' : ''}</Link>
            <small>Scan #{scan.id} · {scan.size_bytes.toLocaleString()} bytes{scan.parent_scan_id ? ` · Parent #${scan.parent_scan_id}` : ''}</small></td>
            <td>{scan.role}</td><td><span className={`health-pill ${['failed', 'skipped'].includes(scan.status) ? 'health-failed' : ''}`}>{scan.status}</span></td>
            <td className={['high', 'critical'].includes(scan.risk_level) ? 'risk-high' : ''}>{riskText(scan)}</td>
            <td><time dateTime={scan.created_at}>{displayTime(scan.created_at)}</time></td></tr>)}</tbody></table></div>}
      <div className="history-pagination"><p className="muted">{page.items.length} shown · Registration time/ID order{afterId ? ' · Historical page: auto-refresh paused' : ''}</p>
        <div>{afterId && <Button variant="secondary" onClick={firstPage}>First page</Button>}
          <Button variant="secondary" disabled={!page.next_after_id || !page.next_after_created || batch.isFetching} onClick={() => {
            const next = new URLSearchParams(params); next.set('after_id', String(page.next_after_id)); next.set('after_created', String(page.next_after_created)); setParams(next)
          }}>Next page</Button></div></div>
      <p className="callout"><a href={`/batches/${batchId}`}>Legacy batch fallback</a></p>
    </>}
  </section>
}
