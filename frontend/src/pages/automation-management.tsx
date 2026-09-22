import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import { Button } from '../components/ui/button'
import { Dialog } from '../components/ui/dialog'
import { AutomationExports } from '../components/automation-exports'

export default function AutomationManagement({ session }: { session: Session }) {
  const scanId = Number(useParams().scanId)
  const [confirm, setConfirm] = useState(false)
  const [needsRefresh, setNeedsRefresh] = useState(false)
  const scan = useQuery({ queryKey: ['automation-management', scanId],
    queryFn: ({ signal }) => request('/api/ui/v1/api-ledger/scans/{scan_id}', 'get', { params: { scan_id: scanId }, signal }),
    retry: false, gcTime: 0, refetchOnWindowFocus: false, refetchOnReconnect: false })
  const deletion = useMutation({ retry: false, mutationFn: (fence: { attempt: number; job_revision: number }) =>
    request('/api/ui/v1/api-ledger/scans/{scan_id}', 'delete', { params: { scan_id: scanId }, csrf: session.csrf_token, body: fence }),
    onSettled: () => { setConfirm(false); setNeedsRefresh(true) } })
  const current = !scan.error && !scan.isFetching && !needsRefresh ? scan.data : undefined
  return <section className="page management-page"><h1>Automation scan management</h1>
    <nav className="report-actions"><Link to="/api-ledger">API ledger</Link>{!deletion.isSuccess && <Link to={`/api-ledger/scans/${scanId}`}>Back to report</Link>}</nav>
    <p className="callout">Delete only this scan. Active jobs, registered children, shared samples and undelivered notifications prevent deletion.
      Database deletion commits before sample cleanup; a cleanup failure is reported separately. No automatic retry is performed.</p>
    {scan.error && !deletion.isSuccess && <p role="alert" className="error">{scan.error.message}</p>}
    {deletion.error && <p role="alert" className="error">{deletion.error.message} The request may have reached the server. Refresh and reconcile before continuing.</p>}
    {deletion.data ? <p role="status" className="callout">Scan #{deletion.data.scan_id} deleted.
      {deletion.data.sample_removed ? ' Sample cleanup confirmed.' : ' Sample cleanup was not confirmed; ask an administrator to check storage.'}</p> : <>
      <Button variant="secondary" disabled={scan.isFetching || deletion.isPending || confirm} onClick={async () => {
        deletion.reset(); const result = await scan.refetch(); if (!result.error) setNeedsRefresh(false)
      }}>Refresh scan</Button>
      {scan.isFetching && <p role="status">Loading current scan…</p>}
      {current && <AutomationExports scanId={scanId} disabled={confirm || deletion.isPending} />}
      {current && <article className="submission-card report-engine"><h2>{current.filename}</h2>
        <p>#{scanId} · {current.source} · Client {current.service_client_id ?? 'Unassigned'} · {current.status} · Attempt {current.attempt_count}</p>
        {session.user.role === 'admin' ? <Button variant="destructive" disabled={confirm || deletion.isPending || ['queued', 'running', 'finalizing'].includes(current.status)} onClick={() => setConfirm(true)}>Delete scan</Button>
          : <p>Administrator access is required to delete scans.</p>}
      </article>}
    </>}
    <Dialog open={confirm} onOpenChange={open => { if (!deletion.isPending) setConfirm(open) }} title="Delete automation scan?"
      description={`Permanently delete scan #${scanId} (${current?.filename || ''}) and attempt sample cleanup. This does not delete a batch or its children.`}>
      <div className="report-actions"><Button variant="secondary" disabled={deletion.isPending} onClick={() => setConfirm(false)}>Cancel</Button>
        <Button variant="destructive" disabled={deletion.isPending || !current} onClick={() => { if (current) deletion.mutate({ attempt: current.attempt_count, job_revision: current.job_revision ?? 0 }) }}>Confirm deletion</Button></div>
    </Dialog>
  </section>
}
