import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { request } from '../lib/api'
import { Button } from '../components/ui/button'

export default function ScanPrint({ automation = false }: { automation?: boolean }) {
  const { scanId = '' } = useParams()
  const valid = /^\d+$/.test(scanId) && Number.isSafeInteger(Number(scanId)) && Number(scanId) > 0
  const base = automation ? '/api-ledger' : ''
  const printable = useQuery({ queryKey: ['scan-print', automation, scanId], enabled: valid,
    queryFn: ({ signal }) => request(automation ? '/api/ui/v1/api-ledger/scans/{scan_id}/print' : '/api/ui/v1/scans/{scan_id}/print', 'get', {
      params: { scan_id: Number(scanId) }, signal }),
    staleTime: 0, gcTime: 0, retry: false, refetchOnMount: 'always',
    refetchOnWindowFocus: false, refetchOnReconnect: false, refetchInterval: false })
  if (!valid) return <section className="page"><h1>Invalid scan ID</h1><Link to="/dashboard">Dashboard</Link></section>
  const data = !printable.error && !printable.isFetching ? printable.data : undefined
  return <section className="page print-report"><div className="page-heading print-hidden"><div>
    <p className="eyebrow">{automation ? 'AUTOMATION' : 'MANUAL'} SCAN #{scanId}</p><h1>Printable report</h1>
    <p className="muted">A print-oriented view of the recorded scan. Opening it runs no engine and changes no data.</p></div>
    <div className="report-actions"><Button variant="secondary" disabled={printable.isFetching}
      onClick={() => { void printable.refetch() }}>Refresh report</Button>
      <Button disabled={!data} onClick={() => window.print()}>Print</Button></div></div>
    <p className="print-hidden"><Link to={`${base}/scans/${scanId}`}>Back to report</Link> · <Link to={`${base}/scans/${scanId}/manage`}>Exports and scan management</Link></p>
    <p className="callout print-hidden">Engine output is bounded for printing; each result links to its complete text.
      Recorded risk and coverage describe what was stored, not a guarantee of complete extraction or a clean verdict.</p>
    {printable.isFetching && <p role="status">Loading printable report…</p>}
    {printable.error && <p role="alert" className="error">{printable.error.message}</p>}
    {data && <article className="print-sheet">
      <header className="print-header"><div><p className="eyebrow">MASP ANALYST REPORT</p>
        <h1 className="report-filename">{data.filename}</h1>
        <p className="muted">Scan #{data.scan_id} · {data.source} · {data.case_name || 'No case'} · generated {data.generated_at}</p></div>
        <p className="muted">{data.status} · recorded risk {data.summary.risk_score === null ? 'not scored' : `${data.summary.risk_score} / 100`} · {data.summary.verdict}</p>
      </header>

      <section aria-label="Sample"><h2>Sample</h2><dl className="report-metadata">
        <dt>SHA-256</dt><dd>{data.sha256}</dd>
        <dt>Size</dt><dd>{data.size_bytes.toLocaleString()} bytes</dd>
        <dt>Content type</dt><dd>{data.content_type || 'Unknown'}</dd>
        <dt>Submitted</dt><dd>{data.created_at}</dd>
        <dt>Completed</dt><dd>{data.completed_at || 'Not completed'}</dd>
        <dt>Attempt</dt><dd>{data.attempt_count}</dd>
        {data.note && <><dt>Note</dt><dd>{data.note}</dd></>}
      </dl></section>

      <section aria-label="Decision"><h2>Backend policy decision</h2>
        {data.decision_warning && <p role="alert" className="error">{data.decision_warning}</p>}
        {data.decision ? <><p><strong>{data.decision.label}</strong> — {data.decision.action} · {data.decision.confidence} confidence · {data.decision.policy}</p>
          <p>{data.decision.reason}</p>
          {data.decision.reasons.length > 0 && <ul>{data.decision.reasons.map((reason, index) => <li key={index}>{reason}</li>)}</ul>}</>
          : <p>No decision is recorded for this scan.</p>}
      </section>

      <section aria-label="Detection and coverage"><h2>Detection and coverage</h2><dl className="report-metadata">
        <dt>Detection</dt><dd>{data.summary.detection_label}. {data.summary.detection_detail}</dd>
        <dt>Coverage</dt><dd>{data.summary.coverage_label} ({data.summary.coverage_ran} of {data.summary.coverage_total}). {data.summary.coverage_detail}</dd>
        {data.summary.coverage_unavailable.length > 0 && <><dt>Unavailable</dt><dd>{data.summary.coverage_unavailable.join('; ')}</dd></>}
        {data.summary.assessment_reasons.length > 0 && <><dt>Assessment</dt><dd>{data.summary.assessment_reasons.join('; ')}</dd></>}
      </dl></section>

      <section aria-label="Normalized findings"><h2>Normalized findings</h2>
        {!data.findings.length && <p>No normalized findings were produced for this scan.</p>}
        {data.findings.length > 0 && <div className="history-table-wrap"><table className="history-table"><thead><tr>
          <th>Engine</th><th>Severity</th><th>Finding</th><th>Title</th><th>Evidence</th><th>Classification</th></tr></thead><tbody>
          {data.findings.map((finding, index) => <tr key={index}><td>{finding.engine}</td><td>{finding.severity}</td>
            <td>{finding.finding}</td><td>{finding.title}</td><td>{finding.matched_evidence.join(', ') || '-'}</td>
            <td>{finding.classification.join(', ') || '-'}</td></tr>)}</tbody></table></div>}
        {data.findings_truncated && <p className="muted">Findings list truncated for printing. Download the full export for every finding.</p>}
      </section>

      <section aria-label="Engine results"><h2>Engine results</h2>
        {!data.engines.length && <p>No engine results are available yet.</p>}
        {data.engines.map((engine, index) => <section key={index} className="print-engine" aria-label={`${engine.engine_name} result`}>
          <h3>{engine.engine_name}</h3>
          <p className="muted">{engine.status} · {engine.detected ? 'detected' : 'no detection'} · {engine.severity} · {engine.confidence}% confidence
            {engine.duration_ms === null ? '' : ` · ${engine.duration_ms} ms`}{engine.signature ? ` · ${engine.signature}` : ''}</p>
          {engine.error_message && <p role="alert" className="error">{engine.error_message}</p>}
          <div className="technical-panel"><pre tabIndex={0} aria-label={`${engine.engine_name} raw output text`}>{engine.raw_output || '(empty)'}</pre></div>
          {engine.output_truncated && <p className="muted">Output truncated for printing. Open the scan report to download this engine's complete output.</p>}
        </section>)}
      </section>
    </article>}
  </section>
}
