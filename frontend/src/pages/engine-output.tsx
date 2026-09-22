import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { request } from '../lib/api'
import { Button } from '../components/ui/button'

export default function EngineOutput({ automation = false }: { automation?: boolean }) {
  const { scanId = '', resultId = '' } = useParams()
  const valid = [scanId, resultId].every(id => /^\d+$/.test(id) && Number.isSafeInteger(Number(id)) && Number(id) > 0)
  const output = useQuery({ queryKey: ['engine-output', automation, scanId, resultId], enabled: valid,
    queryFn: ({ signal }) => request(automation ? '/api/ui/v1/api-ledger/scans/{scan_id}/results/{result_id}/full' : '/api/ui/v1/scans/{scan_id}/results/{result_id}/full', 'get', {
      params: { scan_id: Number(scanId), result_id: Number(resultId) }, signal }),
    staleTime: 0, gcTime: 0, retry: false, refetchOnMount: 'always',
    refetchOnWindowFocus: false, refetchOnReconnect: false, refetchInterval: false })
  if (!valid) return <section className="page"><h1>Invalid scan or result ID</h1><Link to="/dashboard">Dashboard</Link></section>
  // Hide the previous output while refreshing or after a failure. Never show a
  // cached result as evidence that a deleted/retried scan still has this output.
  const data = !output.error && !output.isFetching ? output.data : undefined
  return <section className="page"><div className="page-heading"><div><p className="eyebrow">{automation ? 'AUTOMATION' : 'MANUAL'} SCAN #{scanId}</p>
    <h1>Full engine output</h1></div><Button variant="secondary" disabled={output.isFetching}
      onClick={() => { void output.refetch() }}>Refresh output</Button></div>
    <p><Link to={`${automation ? '/api-ledger' : ''}/scans/${scanId}`}>Back to report</Link> · <Link to={`${automation ? '/api-ledger' : ''}/scans/${scanId}/manage`}>{automation ? 'Scan management' : 'Exports and scan management'}</Link></p>
    <p className="callout">One recorded engine result, loaded on request. This is not live output or a policy decision.
      Complete text is shown up to the 2 MiB browser limit. Above it, download the raw output as plain text instead;
      the download is served directly and is never held in this page.</p>
    <p><a href={`/api/ui/v1${automation ? '/api-ledger' : ''}/scans/${scanId}/results/${resultId}/output`}>Download raw output (plain text)</a></p>
    {output.isFetching && <p role="status">Loading full engine output…</p>}
    {output.error && <p role="alert" className="error">{output.error.message} Return to the report for current results.</p>}
    {data && <><h2 className="report-filename">{data.engine_name}</h2><p className="muted">Attempt {data.attempt_count} · Result #{data.result_id}</p>
      <div className="technical-panel">{([
        ['raw_output', 'Raw output'], ['details_json', 'Details JSON'], ['findings_json', 'Findings JSON'],
      ] as const).map(([field, label]) => <section key={field} aria-label={label}><h3>{label}</h3>
        <pre tabIndex={0} aria-label={`${label} text`}>{data[field] || '(empty)'}</pre></section>)}</div>
    </>}
  </section>
}
