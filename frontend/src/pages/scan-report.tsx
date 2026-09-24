import { useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { request, type ScanReport, type ReportEngine } from '../lib/api'
import { Button } from '../components/ui/button'
import { BackLink } from '../components/section-tabs'

export function reportPollInterval(report?: ScanReport) {
  return report && ['queued', 'running', 'finalizing'].includes(report.status) ? 3000 : false
}

function Technical({ scanId, resultId, automation }: { scanId: number; resultId: number; automation: boolean }) {
  const details = useQuery({ queryKey: ['scan-details', automation, scanId, resultId],
    queryFn: ({ signal }) => request(automation ? '/api/ui/v1/api-ledger/scans/{scan_id}/results/{result_id}' : '/api/ui/v1/scans/{scan_id}/results/{result_id}', 'get', { params: { scan_id: scanId, result_id: resultId }, signal }),
    staleTime: 0, gcTime: 0, retry: false })
  return <div className="technical-panel">
    {details.isPending && <p role="status">Loading technical output…</p>}
    {details.error && <p role="alert" className="error">{details.error.message}</p>}
    {details.data && <><p className="muted">On-demand snapshot, not live output. Close and reopen to refresh.</p>
      {details.data.truncated.length > 0 && <p className="callout">Truncated previews: {details.data.truncated.join(', ')}. Open the full engine output to read more.</p>}
      {(['raw_output', 'details_json', 'findings_json'] as const).map(field => <section key={field}>
        <h3>{field.replaceAll('_', ' ')}</h3><pre>{details.data![field] || '(empty)'}</pre></section>)}
    </>}
  </div>
}

function EngineRow({ scanId, engine, automation }: { scanId: number; engine: ReportEngine; automation: boolean }) {
  const [open, setOpen] = useState(false)
  return <article className="submission-card report-engine"><div className="history-heading"><div>
    <h2>{engine.name}</h2><p className="muted">{engine.required ? 'Required detection engine' : 'Additional result'}</p></div>
    <span className={`health-pill ${engine.detected || ['failed', 'skipped', 'missing'].includes(engine.status) ? 'health-failed' : ''}`}>
      {engine.detected ? 'Detected' : engine.status}</span></div>
    {engine.signature && <p className="risk-high">Signature: {engine.signature}</p>}
    {engine.error && <p className="error">{engine.error}</p>}
    {engine.duration_ms !== null && <p className="muted">Duration: {engine.duration_ms.toLocaleString()} ms</p>}
    {engine.result_id !== null && <><Button variant="secondary" aria-expanded={open} onClick={() => setOpen(value => !value)}>
      {open ? 'Hide' : 'Show'} technical output for {engine.name}</Button>
      <p><Link to={`${automation ? '/api-ledger' : ''}/scans/${scanId}/results/${engine.result_id}`}>Full output for {engine.name}</Link></p>
      {open && <Technical automation={automation} scanId={scanId} resultId={engine.result_id} />}</>}
  </article>
}

export default function Report({ automation = false }: { automation?: boolean }) {
  const { scanId = '' } = useParams()
  const [searchParams] = useSearchParams()
  const justAccepted = searchParams.get('accepted') === '1'
  const valid = /^\d+$/.test(scanId) && Number.isSafeInteger(Number(scanId)) && Number(scanId) > 0
  const report = useQuery({ queryKey: ['scan-report', automation, scanId], enabled: valid,
    queryFn: ({ signal }) => request(automation ? '/api/ui/v1/api-ledger/scans/{scan_id}' : '/api/ui/v1/scans/{scan_id}', 'get', { params: { scan_id: Number(scanId) }, signal }), retry: false,
    refetchInterval: query => reportPollInterval(query.state.data), refetchIntervalInBackground: false,
    refetchOnWindowFocus: true, refetchOnMount: 'always', gcTime: 60000 })
  const scan = report.data
  if (!valid) return <section className="page"><h1>Invalid scan ID</h1><Link to={automation ? "/api-ledger" : "/dashboard"}>{automation ? "API ledger" : "Dashboard"}</Link></section>
  // Do not leave an earlier allow card visible when a refresh fails or expires.
  if (report.error) return <section className="page"><h1>Report unavailable</h1><p role="alert" className="error">{report.error.message}</p>
    <Button onClick={() => { void report.refetch() }}>Retry report</Button></section>
  if (!scan) return <section className="page"><p role="status">Loading scan report…</p></section>
  return <section className="page"><div className="page-heading"><div><p className="eyebrow">{automation ? 'AUTOMATION' : 'MANUAL'} SCAN #{scan.id}</p>
    <h1 className="report-filename">{scan.filename}</h1><p className="muted">Status: {scan.status} · Attempt {scan.attempt_count}</p></div>
    <div className="report-actions"><BackLink to={automation ? '/api-ledger' : '/dashboard'} />
      <Button variant="secondary" disabled={report.isFetching} onClick={() => { void report.refetch() }}>{report.isFetching ? 'Refreshing…' : 'Refresh report'}</Button>
      <Link className="button button-secondary" to={`${automation ? '/api-ledger' : ''}/scans/${scan.id}/print`}>Printable report</Link>
      <Link className="button button-secondary" to={automation ? "/api-ledger" : "/dashboard"}>{automation ? "API ledger" : "Dashboard"}</Link></div></div>
    {justAccepted && <p role="status" className="callout">Scan #{scan.id} was stored and queued. This is not a completed scan or a clean verdict:
      workers run the engines asynchronously and this page updates as they finish. <Link to="/scans/new">Submit another sample</Link></p>}
    {automation && <p className="callout">Source: {scan.source} ? Client: {scan.service_client_id ?? 'Unassigned'}. Operator view; accepted routing determines coverage.</p>}
    {automation && <p><Link to={`/api-ledger/scans/${scan.id}/status-json`}>Integration status JSON</Link> ? <Link to={`/api-ledger/scans/${scan.id}/result-json`}>Integration result JSON</Link></p>}
    {scan.warning && <p role="alert" className="error">{scan.warning}</p>}
    <section className={`submission-card report-decision decision-${scan.decision?.action || 'unknown'}`} aria-label="Policy decision">
      <p className="eyebrow">BACKEND POLICY DECISION</p><h2>{scan.decision?.label || 'Decision unavailable'}</h2>
      <p>{scan.decision?.reason || 'A reliable decision cannot be shown from the compact report.'}</p>
      {scan.decision && <><small>Policy: {scan.decision.policy} · Confidence: {scan.decision.confidence}</small>
        <ul>{scan.decision.reasons.map((reason, index) => <li key={index}>{reason}</li>)}</ul></>}
    </section>
    <div className="stats-row"><div><span>Recorded risk</span><strong>{scan.risk_score === null ? '—' : `${scan.risk_score}/100`}</strong></div>
      <div><span>Required coverage</span><strong>{scan.completed_engines}/{scan.required_engines}</strong></div>
      <div><span>Detecting engines</span><strong>{scan.detected_engines}</strong></div></div>
    <p className="callout">Job completion and a low score do not prove full coverage. {scan.required_engines === 0 ? 'No required detection engines: metadata-only coverage.' : scan.coverage_basis !== 'legacy_configuration' ? 'Required engines are resolved from the accepted routing snapshot or historical engine jobs.' : ''}</p>
    {scan.coverage_basis === 'legacy_configuration' && <p className="callout">Legacy scan without a routing snapshot or engine jobs: required engines fall back to current configuration.</p>}
    {scan.unavailable.length > 0 && <section className="error"><h2>Required engines not completed</h2><ul>{scan.unavailable.map((name, index) => <li key={index}>{name}</li>)}</ul></section>}
    {scan.last_error && <section className="error"><h2>Last worker error</h2><p>{scan.last_error}</p></section>}
    <dl className="submission-card report-metadata"><dt>SHA-256</dt><dd>{scan.sha256}</dd><dt>Size</dt><dd>{scan.size_bytes.toLocaleString()} bytes</dd>
      <dt>Case</dt><dd>{scan.case_name}</dd><dt>Submitted (server time)</dt><dd>{scan.created_at}</dd>
      {scan.note && <><dt>Analyst note</dt><dd>{scan.note}</dd></>}</dl>
    <div className="history-heading"><h2>Engine results</h2><p className="muted">Technical output loads only when opened.</p></div>
    <div className="report-engines">{scan.engines.map(engine => <EngineRow key={`${scan.attempt_count}-${engine.result_id ?? engine.name}`} scanId={scan.id} engine={engine} automation={automation} />)}</div>
    {scan.engines.length === 0 && <p className="empty">No engine results recorded yet.</p>}
    {scan.batch_id !== null && <p className="callout"><Link to={`${automation ? '/api-ledger' : ''}/batches/${scan.batch_id}`}>Open batch overview</Link> · <Link to={`${automation ? "/api-ledger" : ""}/scans/${scan.id}/children`}>Browse registered direct children</Link></p>}
    <p className="callout"><Link to={`${automation ? '/api-ledger' : ''}/scans/${scan.id}/manage`}>{automation ? 'Scan management' : 'Exports and scan management'}</Link>
      {scan.parent_scan_id && <> · <Link to={`${automation ? '/api-ledger' : ''}/scans/${scan.parent_scan_id}`}>Parent scan</Link></>}</p>
  </section>
}
