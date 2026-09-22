import { useEffect, useRef, useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import { Dialog } from '../components/ui/dialog'
import { Button } from '../components/ui/button'

type Candidate = { scan_id: number; attempt: number; job_revision: number }

export default function ApiLedger({ session }: { session?: Session }) {
  const [selected, setSelected] = useState<number[]>([])
  const [draft, setDraft] = useState<Candidate[] | null>(null)
  const [busy, setBusy] = useState(false)
  const sending = useRef(false)
  const [requiresRefresh, setRequiresRefresh] = useState(false)
  const [receipt, setReceipt] = useState('')
  const [error, setError] = useState('')
  const admin = session?.user.role === 'admin' 
  const [params, setParams] = useSearchParams()
  const query = new URLSearchParams(params)
  query.set('limit', '20')
  const scans = useQuery({ queryKey: ['api-ledger', query.toString()],
    queryFn: ({ signal }) => request('/api/ui/v1/api-ledger', 'get', { query, signal }),
    retry: false, staleTime: 0, gcTime: 0, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })
  const queryKey = query.toString()
  useEffect(() => { setSelected([]); setDraft(null); setRequiresRefresh(false); setReceipt(''); setError('') }, [queryKey])
  const locked = busy || draft !== null
  async function refresh() {
    setSelected([])
    const updated = await scans.refetch()
    if (!updated.isError) setRequiresRefresh(false)
  }
  async function deleteSelected() {
    if (!session || !draft || sending.current) return
    sending.current = true; setBusy(true); setError(''); setReceipt('')
    try {
      const result = await request('/api/ui/v1/api-ledger/scans', 'delete', {
        csrf: session.csrf_token, body: { scans: draft },
      })
      const ids = (values: number[]) => values.length ? values.join(', ') : 'none'
      setReceipt(`Deleted IDs: ${ids(result.deleted_ids)}. Blocked IDs: ${ids(result.blocked_ids)}. File cleanup unconfirmed IDs: ${ids(result.cleanup_failed_ids)}.`)
    } catch (failure) {
      setError(`${failure instanceof Error ? failure.message : 'Deletion failed.'} The request may have partially completed. Refresh and review current records before another deletion.`)
    } finally {
      setRequiresRefresh(true); setSelected([]); setDraft(null); setBusy(false); sending.current = false
    }
  }
  function filter(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (locked) return
    const form = new FormData(event.currentTarget), next = new URLSearchParams()
    for (const key of ['q', 'source', 'status', 'risk', 'client_id']) {
      const value = String(form.get(key) || '').trim()
      if (value && value !== 'all') next.set(key, value)
    }
    if (form.get('unassigned')) { next.delete('client_id'); next.set('unassigned', 'true') }
    setParams(next)
  }
  function paginate(before?: number) {
    const next = new URLSearchParams(params)
    if (before) next.set('before', String(before)); else next.delete('before')
    setParams(next)
  }
  return <section className="page management-page"><div className="page-heading"><div><p className="eyebrow">AUTOMATION HISTORY</p>
    <h1>API ledger</h1><p className="muted">API and ICAP submissions. Manual scans and archive children are excluded.</p></div>
    <Button variant="secondary" disabled={scans.isFetching || locked} onClick={() => { void refresh() }}>Refresh ledger</Button></div>
    {admin && <Button variant="destructive" disabled={locked || scans.isFetching || !!scans.error || requiresRefresh || selected.length === 0}
      onClick={() => setDraft((scans.data?.items ?? []).filter(scan => selected.includes(scan.id)).map(scan => ({
        scan_id: scan.id, attempt: scan.attempt_count, job_revision: scan.job_revision,
      })))}>Delete selected ({selected.length})</Button>}
    {receipt && <p role="status" className="callout">{receipt}</p>}
    {error && <p role="alert" className="error">{error}</p>}
    {requiresRefresh && <p className="callout">Refresh ledger to review the current records before selecting again.</p>}
    <p className="callout">Recorded risk is not a clean verdict or proof of complete coverage. Open a report to review the backend decision.
      Deferred intake appears only after a scan is created. Client names reflect current configuration; IDs identify recorded ownership.</p>
    <form key={params.toString()} onSubmit={filter} className="submission-card" aria-label="Ledger filters"><fieldset disabled={locked} className="history-filters">
      <label>Filename, hash or case<input name="q" maxLength={200} defaultValue={params.get('q') || ''} /></label>
      <label>Source<select name="source" defaultValue={params.get('source') || 'all'}><option value="all">API and ICAP</option><option value="api">API</option><option value="icap">ICAP</option></select></label>
      <label>Status<select name="status" defaultValue={params.get('status') || 'all'}>{['all', 'active', 'queued', 'running', 'finalizing', 'completed', 'partial', 'failed', 'skipped'].map(value => <option key={value} value={value}>{value}</option>)}</select></label>
      <label>Recorded risk<select name="risk" defaultValue={params.get('risk') || 'all'}>{['all', 'pending', 'info', 'metadata_only', 'low', 'medium', 'high', 'critical'].map(value => <option key={value} value={value}>{value}</option>)}</select></label>
      <label>Client ID<input name="client_id" type="number" min={1} max={9007199254740991} step={1} defaultValue={params.get('client_id') || ''} /></label>
      <label><input name="unassigned" type="checkbox" defaultChecked={params.get('unassigned') === 'true'} /> Unassigned only (overrides client ID)</label>
      <Button type="submit" disabled={scans.isFetching}>Apply filters</Button><Button type="button" variant="secondary" onClick={() => setParams({})}>Reset filters</Button>
    </fieldset></form>
    {scans.isPending && <p role="status">Loading automation history…</p>}
    {scans.error && <p role="alert" className="error">{scans.error.message}</p>}
    {!requiresRefresh && !scans.error && scans.data && <>
      {!scans.data.items.length && <p>No automation scans match these filters.</p>}
      {scans.data.items.map(scan => <article className="submission-card report-engine" key={scan.id}>
        {admin && <label><input type="checkbox" aria-label={`Select scan ${scan.id}`} checked={selected.includes(scan.id)}
          disabled={locked || scans.isFetching || ['queued', 'running', 'finalizing'].includes(scan.status) || (!selected.includes(scan.id) && selected.length >= 20)}
          onChange={() => setSelected(current => current.includes(scan.id) ? current.filter(id => id !== scan.id) : [...current, scan.id])} /> Select scan #{scan.id}</label>}
        <h2>{scan.filename}</h2><p className="muted">#{scan.id} · {scan.source.toUpperCase()} · {scan.size_bytes.toLocaleString()} bytes · {scan.case_name || 'No case'}</p>
        <p className="report-hash">{scan.sha256}</p>
        <p>{scan.service_client_id === null ? 'Unassigned client' : `Client #${scan.service_client_id} · ${scan.client_name || 'Name unavailable'}`}</p>
        <p>Status: {scan.status} · Recorded risk: {scan.risk_score === null ? 'Not scored' : `${scan.risk_score} / 100 · ${scan.risk_level}`}</p>
        <p className="muted">Submitted: {scan.created_at}</p>
        <nav className="report-actions"><Link to={`/api-ledger/scans/${scan.id}`}>Open report</Link>
          {scan.batch_id !== null && <Link to={`/api-ledger/batches/${scan.batch_id}`}>Open batch</Link>}
          {scan.service_client_id !== null && <Button variant="secondary" disabled={locked} onClick={() => {
            const next = new URLSearchParams(params); next.set('client_id', String(scan.service_client_id)); next.delete('unassigned'); next.delete('before'); setParams(next)
          }}>Filter client #{scan.service_client_id}</Button>}</nav>
      </article>)}
      <div className="history-pagination"><Button variant="secondary" disabled={locked || scans.isFetching || !params.get('before')} onClick={() => paginate()}>Newest scans</Button>
        <Button variant="secondary" disabled={locked || scans.isFetching || !scans.data.next_before} onClick={() => paginate(scans.data!.next_before!)}>Older scans</Button></div>
    </>}
    <Dialog open={draft !== null} onOpenChange={open => { if (!open && !busy) setDraft(null) }} title="Delete selected automation scans?"
      description="Only these records will be checked and deleted individually. Active scans, registered parents, shared samples and pending notifications remain protected. This does not delete batches recursively.">
      <p>Scan IDs: {draft?.map(row => row.scan_id).join(', ')}</p>
      <div className="report-actions"><Button variant="secondary" disabled={busy} onClick={() => setDraft(null)}>Cancel</Button>
        <Button variant="destructive" disabled={busy || !draft?.length} onClick={() => { void deleteSelected() }}>{busy ? 'Deleting?' : 'Confirm deletion'}</Button></div>
    </Dialog>
  </section>
}
