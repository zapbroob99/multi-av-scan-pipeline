import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { request } from '../lib/api'
import { Button } from '../components/ui/button'

export default function AutomationResult({ status = false }: { status?: boolean }) {
  const kind = status ? 'status' : 'result'
  const { scanId = '' } = useParams()
  const valid = /^\d+$/.test(scanId) && Number.isSafeInteger(Number(scanId)) && Number(scanId) > 0
  const result = useQuery({ queryKey: ['automation-result-json', scanId, kind], enabled: valid,
    queryFn: ({ signal }) => request(status ? '/api/ui/v1/api-ledger/scans/{scan_id}/status-json' : '/api/ui/v1/api-ledger/scans/{scan_id}/result-json', 'get', {
      params: { scan_id: Number(scanId) }, signal }),
    staleTime: 0, gcTime: 0, retry: false, refetchOnMount: 'always',
    refetchOnWindowFocus: false, refetchOnReconnect: false, refetchInterval: false })
  if (!valid) return <section className="page"><h1>Invalid scan ID</h1><Link to="/api-ledger">API ledger</Link></section>
  const data = !result.error && !result.isFetching ? result.data : undefined
  return <section className="page"><div className="page-heading"><div><p className="eyebrow">AUTOMATION SCAN #{scanId}</p>
    <h1>Integration {kind} JSON</h1></div><Button variant="secondary" disabled={result.isFetching}
      onClick={() => { void result.refetch() }}>Refresh JSON</Button></div>
    <p><Link to={`/api-ledger/scans/${scanId}`}>Back to report</Link></p>
    <p className="callout">{status ? 'A snapshot of integration status. Queue counts cover all sources; expected engines reflect current eligibility of accepted instances, not required detection coverage.' : 'A snapshot of the completed integration result, with private engine output omitted.'}
      Embedded API links require integration authentication. No automatic refresh.
      Large or incomplete records may be unavailable here; consult the report for details.</p>
    {result.isFetching && <p role="status">Loading {kind} JSON…</p>}
    {result.error && <p role="alert" className="error">{result.error.message}</p>}
    {data && <div className="technical-panel"><pre tabIndex={0} aria-label={`Integration ${kind} JSON text`}>{data.content}</pre></div>}
  </section>
}
