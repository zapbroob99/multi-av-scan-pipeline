import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import { Button } from '../components/ui/button'
import { Dialog } from '../components/ui/dialog'

export default function ScanManagement({ session }: { session: Session }) {
  const { scanId = '' } = useParams()
  const client = useQueryClient()
  const [confirmation, setConfirmation] = useState<{ action: 'retry' | 'delete'; attempt: number; job_revision: number } | null>(null)
  const [receipt, setReceipt] = useState('')
  const [deleted, setDeleted] = useState(false)
  const valid = /^\d+$/.test(scanId) && Number.isSafeInteger(Number(scanId)) && Number(scanId) > 0
  const params = { scan_id: Number(scanId) }
  const report = useQuery({ queryKey: ['scan-report', scanId], enabled: valid && !receipt,
    queryFn: ({ signal }) => request('/api/ui/v1/scans/{scan_id}', 'get', { params, signal }),
    retry: false, refetchOnMount: 'always', refetchOnWindowFocus: true, gcTime: 60000 })
  const operation = useMutation({ retry: false,
    mutationFn: async ({ action, attempt, job_revision }: { action: 'retry' | 'delete'; attempt: number; job_revision: number }) => {
      const options = { params, csrf: session.csrf_token, body: { attempt, job_revision } }
      return action === 'retry' ? request('/api/ui/v1/scans/{scan_id}/retry', 'post', options)
        : request('/api/ui/v1/scans/{scan_id}', 'delete', options)
    },
    onMutate: async () => {
      await client.cancelQueries({ predicate: query => ['scan-report', 'scan-details', 'archive-children', 'dashboard'].includes(String(query.queryKey[0])) })
    },
    onSuccess: result => {
      const removed = result.status === 'deleted'
      setDeleted(removed)
      setReceipt(removed ? `Scan record deleted.${!result.sample_removed ? ' Sample file removal was not confirmed; ask an administrator to check storage cleanup.' : ' Sample file removed.'}`
        : 'Retry accepted. The scan has been queued; engine execution and completion are pending.')
      client.removeQueries({ predicate: query => ['scan-details', 'archive-children'].includes(String(query.queryKey[0])) })
    },
    onSettled: async () => {
      setConfirmation(null)
      client.removeQueries({ queryKey: ['scan-details'] })
      await Promise.all([client.resetQueries({ queryKey: ['scan-report', scanId], exact: true }),
        ...['archive-children', 'dashboard'].map(key => client.invalidateQueries({ queryKey: [key] }))])
    },
  })
  const download = useMutation({ retry: false,
    mutationFn: async ({ scope, format }: { scope: 'summary' | 'full'; format: 'json' | 'csv' }) => {
    const options = { params, query: new URLSearchParams({ format }) }
    const exported = scope === 'full'
      ? await request('/api/ui/v1/scans/{scan_id}/export', 'get', options)
      : await request('/api/ui/v1/scans/{scan_id}/summary-export', 'get', options)
    const url = URL.createObjectURL(new Blob([exported.content], { type: `${exported.media_type};charset=utf-8` }))
    const anchor = document.createElement('a')
    anchor.href = url; anchor.download = exported.filename; document.body.append(anchor)
    anchor.click(); anchor.remove()
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
  } })
  const scan = report.error ? undefined : report.data
  const busy = operation.isPending || download.isPending
  const active = scan && ['queued', 'running', 'finalizing'].includes(scan.status)
  if (!valid) return <section className="page"><h1>Invalid scan ID</h1><Link to="/dashboard">Dashboard</Link></section>
  return <section className="page management-page"><div className="page-heading"><div><p className="eyebrow">MANUAL SCAN #{scanId}</p>
    <h1>Exports and scan management</h1></div><Link className="button button-secondary" to="/dashboard">Dashboard</Link></div>
    {!deleted && <p><Link to={`/scans/${scanId}`}>Back to report</Link></p>}
    {receipt && <p role="status" className="callout">{receipt}</p>}
    {operation.error && <p role="alert" className="error">{operation.error.message} The request may have reached the server. Check the report or Dashboard before trying again.</p>}
    {!receipt && <>
      {report.isPending && <p role="status">Loading scan...</p>}
      {report.error && <p role="alert" className="error">{report.error.message}</p>}
      <Button variant="secondary" disabled={busy || report.isFetching} onClick={() => { void report.refetch() }}>Refresh scan</Button>
      {scan && <><section className="submission-card"><h2 className="report-filename">{scan.filename}</h2>
        <p>Status: {scan.status} · Attempt {scan.attempt_count}</p></section>
        <section className="submission-card"><h2>Export report summary</h2>
          <p>Download a fresh backend summary with policy decision and engine coverage. Text previews are bounded. Use the full JSON export below for raw output and complete findings; archive children remain on the report.</p>
          <div className="report-actions"><Button variant="secondary" disabled={busy} onClick={() => download.mutate({ scope: 'summary', format: 'json' })}>Download summary JSON</Button>
            <Button variant="secondary" disabled={busy} onClick={() => download.mutate({ scope: 'summary', format: 'csv' })}>Download summary CSV</Button></div>
          {download.isPending && <p role="status">Preparing download...</p>}
          {download.error && <p role="alert" className="error">{download.error.message}</p>}
        </section>
        <section className="submission-card"><h2>Export full report</h2>
          <p>JSON includes complete raw engine output, structured details and normalized findings from one database snapshot. CSV contains normalized report rows and engine errors; use JSON when raw output is required. Browser exports are limited to 2 MiB and never include the stored sample path or sample bytes.</p>
          <div className="report-actions"><Button variant="secondary" disabled={busy} onClick={() => download.mutate({ scope: 'full', format: 'json' })}>Download full JSON</Button>
            <Button variant="secondary" disabled={busy} onClick={() => download.mutate({ scope: 'full', format: 'csv' })}>Download full CSV</Button></div>
        </section>
        <section className="submission-card"><h2>Manage this scan</h2>
          <p>Retry replaces this scan's engine results and can consume external reputation quota. Existing archive child records remain.</p>
          {active && <p className="callout">Active scans cannot be retried or deleted. Refresh after completion.</p>}
          <div className="report-actions"><Button disabled={busy || report.isFetching || active} onClick={() => setConfirmation({ action: 'retry', attempt: scan.attempt_count, job_revision: scan.job_revision ?? 0 })}>Retry scan</Button>
            {session.user.role === 'admin' && <Button variant="destructive" disabled={busy || report.isFetching || active} onClick={() => setConfirmation({ action: 'delete', attempt: scan.attempt_count, job_revision: scan.job_revision ?? 0 })}>Delete scan</Button>}</div>
          <p className="muted">Deletion requires an administrator. Scans with registered children, shared samples or undelivered notifications are protected.</p>
        </section></>}
      <p className="callout"><Link to={`/scans/${scanId}`}>Open an engine's full output from the report</Link> · <a href={`/scans/${scanId}/export.json`}>Legacy JSON fallback</a> · <a href={`/scans/${scanId}/export.csv`}>Legacy CSV fallback</a></p>
    </>}
    <Dialog open={confirmation !== null} onOpenChange={open => { if (!open && !busy) setConfirmation(null) }}
      title={confirmation?.action === 'delete' ? 'Delete this scan?' : 'Retry this scan?'}
      description={confirmation?.action === 'delete' ? 'This permanently removes this scan record and attempts to remove its stored sample. Export any required report first.'
        : 'Previous engine results will be replaced. External reputation quota may be used. Registered archive children remain.'}>
      <div className="report-actions"><Button variant="secondary" disabled={busy} onClick={() => setConfirmation(null)}>Cancel</Button>
        <Button disabled={busy} onClick={() => { if (confirmation) operation.mutate(confirmation) }}>{operation.isPending ? 'Submitting...' : 'Confirm'}</Button></div>
    </Dialog>
  </section>
}
