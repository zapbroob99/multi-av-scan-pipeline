import type { FormEvent } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { request, type ArchivePage } from '../lib/api'
import { Button } from '../components/ui/button'

const active = (status: string) => ['queued', 'running', 'finalizing'].includes(status)
export function archivePollInterval(after: string, page?: ArchivePage) {
  return !after && page && (active(page.parent_status) || page.items.some(item => active(item.status))) ? 3000 : false
}

export default function ArchiveChildren({ automation = false }: { automation?: boolean }) {
  const scope = automation ? '/api-ledger' : ''
  const { scanId = '' } = useParams()
  const [params, setParams] = useSearchParams()
  const after = params.get('after') || '', q = params.get('q') || '', status = params.get('status') || 'all'
  const query = new URLSearchParams({ limit: '20', q, status,
    ...(after ? { after, attempt: params.get('attempt') || '' } : {}) }).toString()
  const valid = /^\d+$/.test(scanId) && Number.isSafeInteger(Number(scanId)) && Number(scanId) > 0
  const children = useQuery({ queryKey: ['archive-children', automation, scanId, query], enabled: valid,
    queryFn: ({ signal }) => request(automation ? '/api/ui/v1/api-ledger/scans/{scan_id}/children' : '/api/ui/v1/scans/{scan_id}/children', 'get', { params: { scan_id: Number(scanId) }, query: new URLSearchParams(query), signal }), retry: false,
    refetchInterval: query => archivePollInterval(after, query.state.data), refetchIntervalInBackground: false,
    refetchOnWindowFocus: !after, refetchOnMount: 'always', gcTime: 60000 })
  const page = children.error ? undefined : children.data
  function firstPage() { const next = new URLSearchParams(params); next.delete('after'); next.delete('attempt'); setParams(next) }
  function filter(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget), next = new URLSearchParams()
    for (const key of ['q', 'status']) {
      const value = String(data.get(key) || '').trim()
      if (value && value !== 'all') next.set(key, value)
    }
    setParams(next)
  }
  if (!valid) return <section className="page"><h1>Invalid scan ID</h1><Link to={automation ? "/api-ledger" : "/dashboard"}>{automation ? "API ledger" : "Dashboard"}</Link></section>
  return <section className="page"><div className="page-heading"><div><p className="eyebrow">REGISTERED CHILD SCANS</p>
    <h1>Archive contents</h1><p className="muted report-filename">{page?.parent_filename || `Scan #${scanId}`}</p></div>
    <div className="report-actions"><Link className="button button-secondary" to={`${scope}/scans/${scanId}`}>Parent report</Link>
      <Button variant="secondary" disabled={children.isFetching} onClick={() => { void children.refetch() }}>Refresh contents</Button></div></div>
    <p className="callout">Only direct, registered child scans are shown, not a complete archive inventory. Empty or completed rows do not prove clean/full coverage. Reading this page never extracts or executes files.</p>
    <form key={`${scanId}-${params.toString()}`} className="history-filters" onSubmit={filter} aria-label="Archive filters">
      <label className="search"><input name="q" aria-label="Search archive paths" defaultValue={q} maxLength={200} placeholder="Path or filename…" /></label>
      <label>Status<select name="status" defaultValue={status}>{['all', 'active', 'queued', 'running', 'finalizing', 'completed', 'partial', 'failed', 'skipped'].map(value =>
        <option key={value} value={value}>{value === 'all' ? 'All statuses' : value}</option>)}</select></label>
      <Button variant="secondary">Apply filters</Button><Button variant="secondary" type="button" onClick={() => setParams({})}>Reset</Button>
    </form>
    {children.isPending && <p className="skeleton" role="status">Loading child scans…</p>}
    {children.error ? <section className="error" role="alert"><p>{children.error.message}</p>
      <Button variant="secondary" onClick={firstPage}>Return to first page</Button></section> : page && <>
      <p className="muted archive-context">Parent: {page.parent_status} · Attempt {page.attempt_count} · Mode: {page.archive_mode || 'Unknown'}.
        {' '}Retries may retain previously registered children; this is not a fresh-extraction guarantee.</p>
      {page.items.length === 0 ? <section className="empty"><h2>No registered children on this page</h2>
        <p>Filters may exclude records. Lazy extraction may not have run, may have been skipped or may have failed. Check the parent report.</p></section> :
        <div className="history-table-wrap" tabIndex={0} role="region" aria-label="Archive child scans"><table className="history-table">
          <thead><tr><th scope="col">Archive path</th><th scope="col">Status</th><th scope="col">Recorded risk</th><th scope="col">Navigation</th></tr></thead>
          <tbody>{page.items.map(child => <tr key={child.id}><td><Link className="sample-link" to={`${scope}/scans/${child.id}`}>{child.path}{child.path_truncated ? '…' : ''}</Link>
            <small>Scan #{child.id} · {child.size_bytes.toLocaleString()} bytes{child.path_truncated ? ' · Path preview truncated' : ''}</small></td>
            <td><span className={`health-pill ${['failed', 'skipped'].includes(child.status) ? 'health-failed' : ''}`}>{child.status}</span></td>
            <td>{active(child.status) ? 'Pending' : child.risk_score === null ? 'Not scored' : `${child.risk_score}/100 · ${child.risk_level}`}</td>
            <td>{child.has_children ? <Link to={`${scope}/scans/${child.id}/children`}>Browse children of #{child.id}</Link> : <Link to={`${scope}/scans/${child.id}`}>Open report #{child.id}</Link>}</td>
          </tr>)}</tbody></table></div>}
      <div className="history-pagination"><p className="muted">{page.items.length} shown · Registration ID order{after ? ' · Historical page: auto-refresh paused' : ''}</p>
        <div>{after && <Button variant="secondary" onClick={firstPage}>First page</Button>}
          <Button variant="secondary" disabled={!page.next_after || children.isFetching} onClick={() => {
            const next = new URLSearchParams(params); next.set('after', String(page.next_after)); next.set('attempt', String(page.attempt_count)); setParams(next)
          }}>Next page</Button></div></div>
      <p className="callout">{page.parent_scan_id && <><Link to={`${scope}/scans/${page.parent_scan_id}/children`}>Up one level</Link> · </>}
        {page.batch_id && <><Link to={`${scope}/batches/${page.batch_id}`}>Batch overview</Link> · </>}
        <a href={`/scans/${scanId}`}>Legacy report: fallback</a></p>
    </>}
  </section>
}
