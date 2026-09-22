import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import type { components } from '../lib/api.generated'
import { Button } from '../components/ui/button'
import { Dialog } from '../components/ui/dialog'

type RunBody = components['schemas']['RetentionRunBody']

export default function Retention({ session }: { session: Session }) {
  const client = useQueryClient()
  const [params, setParams] = useSearchParams()
  const after = params.get('after') || ''
  const [confirmation, setConfirmation] = useState<RunBody | null>(null)
  const [needsRefresh, setNeedsRefresh] = useState(false)
  const preview = useQuery({ queryKey: ['retention-preview', after],
    queryFn: ({ signal }) => request('/api/ui/v1/system/retention', 'get', { signal,
      query: new URLSearchParams(after ? { after } : {}) }),
    retry: false, gcTime: 0, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })
  const action = useMutation({ retry: false, mutationFn: (body: RunBody) =>
    request('/api/ui/v1/system/retention/run', 'post', { csrf: session.csrf_token, body }),
    onSettled: () => {
      setConfirmation(null); setNeedsRefresh(true)
      void client.invalidateQueries({ predicate: q => q.queryKey[0] !== 'retention-preview' && q.queryKey[0] !== 'session' })
    } })
  const busy = preview.isFetching || action.isPending || confirmation !== null
  const data = !preview.error && !needsRefresh ? preview.data : undefined
  return <section className="page management-page"><div className="page-heading"><div><p className="eyebrow">SYSTEM</p>
    <h1>Retention cleanup</h1><p className="muted">Review expired records before permanently deleting a bounded batch.</p></div>
    <Button variant="secondary" disabled={busy} onClick={async () => { action.reset(); const result = await preview.refetch(); if (!result.error) setNeedsRefresh(false) }}>Refresh preview</Button></div>
    <nav className="report-actions"><Link to="/system/overview">System overview</Link><Link to="/system">Worker management</Link></nav>
    <p className="callout">Includes all scan sources and archive children. Each run is limited to 20 displayed records or the smaller server batch limit.
      Active scans, records with children, shared samples and undelivered notifications are protected. Records can become blocked after preview.</p>
    {preview.isPending && <p role="status">Loading retention preview…</p>}
    {preview.error && <p role="alert" className="error">{preview.error.message}</p>}
    {action.error && <p role="alert" className="error">{action.error.message} Some records may already have been deleted. Refresh and reconcile before any new run; this request will not be replayed.</p>}
    {action.data && <div role="status" className="callout"><p>Deleted IDs: {action.data.deleted_ids.join(', ') || 'None'}</p>
      <p>Blocked IDs: {action.data.blocked_ids.join(', ') || 'None'}</p><p>File cleanup failed for deleted IDs: {action.data.cleanup_failed_ids.join(', ') || 'None'}</p></div>}
    {needsRefresh && <p>Refresh the preview before reviewing another batch.</p>}
    {data && <>
      <p className="muted">Server policy: {data.days} days; batch limit {data.batch_size}. {data.cutoff ? `Candidates created before ${data.cutoff}.` : 'Retention cleanup is disabled.'}</p>
      {!!data.items.length && <div className="history-table-wrap" role="region" aria-label="Retention candidates" tabIndex={0}>
        <table className="history-table"><thead><tr><th>Scan</th><th>Filename</th><th>Source</th><th>Status</th><th>Created</th></tr></thead><tbody>
          {data.items.map(item => <tr key={item.scan_id}><td>#{item.scan_id}</td><td>{item.filename}</td><td>{item.source}</td><td>{item.status}</td><td>{item.created_at}</td></tr>)}
        </tbody></table></div>}
      {!data.items.length && data.cutoff && <p>No expired inactive records on this page.</p>}
      <div className="history-pagination"><Button variant="secondary" disabled={busy || !after} onClick={() => setParams({})}>First candidates</Button>
        <Button variant="secondary" disabled={busy || !data.next_after} onClick={() => setParams({ after: String(data.next_after) })}>Next candidates</Button>
        <Button variant="destructive" disabled={busy || !data.items.length || !data.cutoff} onClick={() => setConfirmation({ days: data.days, batch_size: data.batch_size,
          scans: data.items.map(({ scan_id, attempt, job_revision }) => ({ scan_id, attempt, job_revision })) })}>Review deletion</Button></div>
    </>}
    <Dialog open={confirmation !== null} onOpenChange={open => { if (!open && !action.isPending) setConfirmation(null) }}
      title="Permanently delete expired records?" description={`Delete scan records and stored sample files for IDs ${confirmation?.scans.map(row => row.scan_id).join(', ') || ''}. Each record commits separately. Protected or changed records will be blocked.`}>
      <div className="report-actions"><Button variant="secondary" disabled={action.isPending} onClick={() => setConfirmation(null)}>Cancel</Button>
        <Button variant="destructive" disabled={action.isPending} onClick={() => { if (confirmation) action.mutate(confirmation) }}>{action.isPending ? 'Deleting…' : 'Confirm retention deletion'}</Button></div>
    </Dialog>
  </section>
}
