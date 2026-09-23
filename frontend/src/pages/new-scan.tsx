import { useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowUpRight, Upload } from 'lucide-react'
import { request, ApiError, type Session } from '../lib/api'
import { Button } from '../components/ui/button'

export default function NewScan({ session }: { session: Session }) {
  const client = useQueryClient()
  const navigate = useNavigate()
  const [validation, setValidation] = useState('')
  const options = useQuery({ queryKey: ['submission-options'],
    queryFn: ({ signal }) => request('/api/ui/v1/scans/options', 'get', { signal }), staleTime: 0 })
  const upload = useMutation({ mutationFn: (body: FormData) => request('/api/ui/v1/scans', 'post', {
    body, csrf: session.csrf_token,
  }), retry: false, onSuccess: accepted => {
    void client.invalidateQueries({ queryKey: ['dashboard'] })
    navigate(`/scans/${accepted.scan_id}?accepted=1`)
  } })
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (upload.isPending || upload.isSuccess) return
    setValidation('')
    const body = new FormData(event.currentTarget)
    const file = (event.currentTarget.elements.namedItem('sample') as HTMLInputElement).files?.[0]
    if (!file?.name) { setValidation('Select one sample file.'); return }
    body.set('sample', file)
    if (!options.data) { setValidation('Load submission limits before uploading.'); return }
    const limit = Math.min(options.data.file_max_bytes ?? Infinity, options.data.body_max_bytes)
    if (file.size >= options.data.body_max_bytes || file.size > limit) {
      setValidation('This file exceeds the current upload limits. No upload was sent.'); return
    }
    upload.mutate(body)
  }
  const uncertain = upload.error && (!(upload.error instanceof ApiError) || upload.error.status >= 500)
  return <section className="page"><div className="page-heading"><div><p className="eyebrow">MANUAL INTAKE</p>
    <h1>Submit sample</h1><p className="muted">Store a file and queue it for the configured scan engines.</p></div>
    <Link className="button button-secondary" to="/dashboard">Dashboard</Link></div>
    {upload.data ? <section className="submission-card" aria-live="polite"><h2>Scan accepted</h2>
      <p className="notice">Scan #{upload.data.scan_id} was stored and queued. This is not a completed scan or a clean verdict.</p>
      <p className="muted">Workers execute the engines asynchronously. The report shows progress, detection coverage and the policy decision.</p>
      <div className="dialog-actions"><Button variant="secondary" onClick={() => upload.reset()}>Submit another sample</Button>
        <Link className="button button-primary" to={`/scans/${upload.data.scan_id}`}><ArrowUpRight size={16} />Open scan report</Link></div>
    </section> : <div className="submission-layout"><form className="submission-card" onSubmit={submit}>
      <fieldset disabled={upload.isPending}>
        <label>Sample file<input type="file" name="sample" required /></label>
        <p className="muted submission-help">One file per submission. Archives use the existing lazy-extraction workflow. File contents are never previewed or executed in the browser.</p>
        <div className="field-grid"><label>Case name<input name="case_name" maxLength={200} placeholder="IR-2026-001" /></label>
          <label>Priority<select name="priority" defaultValue="Normal"><option>Normal</option><option>High</option><option>Low</option></select></label></div>
        <label>Analyst note<textarea name="note" rows={4} maxLength={4000} placeholder="Source, ticket or handling notes" /></label>
        {validation && <p role="alert" className="error">{validation}</p>}
        {upload.error && <p role="alert" className="error">{upload.error.message}{uncertain && ' Submission may have reached the server. Check Dashboard before retrying to avoid duplicate scans.'}</p>}
        <div className="dialog-actions"><Button disabled={upload.isPending || !options.data || !options.data.enabled_engine_count}>
          <Upload size={16} />{upload.isPending ? 'Sending sample…' : 'Create scan'}</Button></div>
      </fieldset>
      {upload.isPending && <p role="status" className="muted">Uploading and awaiting acceptance. Keep this page open; do not submit the file again.</p>}
    </form><aside className="submission-card"><h2>Submission policy</h2>
      {options.isPending && <p role="status" className="muted">Loading limits…</p>}
      {options.error && <><p role="alert" className="error">{options.error.message}</p><Button variant="secondary" onClick={() => { void options.refetch() }}>Retry limits</Button></>}
      {options.data && <><dl className="submission-policy"><dt>Enabled file engines</dt><dd>{options.data.enabled_engine_count}</dd>
        <dt>File size policy</dt><dd>{options.data.file_max_bytes === null ? 'No separate file limit' : `${options.data.file_max_bytes.toLocaleString()} bytes`}</dd>
        <dt>HTTP request ceiling</dt><dd>{options.data.body_max_bytes.toLocaleString()} bytes, including multipart overhead</dd></dl>
        {!options.data.enabled_engine_count && <p className="error">No eligible engines are enabled. Ask an administrator to configure an engine.</p>}
        <p className="callout">Enabled does not mean healthy. Missing workers may delay scanning. Manual scans can use configured external reputation services and their quota.</p>
        <p className="muted submission-help">Server and proxy limits are authoritative and may change. Acceptance does not wait for engines. Uploads are not automatically retried.</p></>}
    </aside></div>}
  </section>
}
