import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { request } from '../lib/api'
import { Button } from '../components/ui/button'

export default function BatchJson({ status = false }: { status?: boolean }) {
  const kind = status ? 'status' : 'result'
  const { batchId = '' } = useParams()
  const valid = /^\d+$/.test(batchId) && Number.isSafeInteger(Number(batchId)) && Number(batchId) > 0
  const result = useQuery({ queryKey: ['automation-batch-json', batchId, kind], enabled: valid,
    queryFn: ({ signal }) => request('/api/ui/v1/api-ledger/batches/{batch_id}/json', 'get', {
      params: { batch_id: Number(batchId) }, query: new URLSearchParams({ kind }), signal }),
    staleTime: 0, gcTime: 0, retry: false, refetchOnMount: 'always',
    refetchOnWindowFocus: false, refetchOnReconnect: false, refetchInterval: false })
  if (!valid) return <section className="page"><h1>Invalid batch ID</h1><Link to="/api-ledger">API ledger</Link></section>
  const data = !result.error && !result.isFetching ? result.data : undefined
  return <section className="page"><div className="page-heading"><div><p className="eyebrow">AUTOMATION BATCH #{batchId}</p>
    <h1>Batch {kind} JSON</h1></div><Button variant="secondary" disabled={result.isFetching}
      onClick={() => { void result.refetch() }}>Refresh JSON</Button></div>
    <p><Link to={`/api-ledger/batches/${batchId}`}>Back to batch overview</Link></p>
    <p className="callout">Complete JSON for up to 20 registered scans. Stored counts can lag workers;
      completion does not prove clean coverage or complete extraction. Larger records remain in the batch overview
      and individual reports. API links require integration authentication. No automatic refresh.</p>
    {result.isFetching && <p role="status">Loading {kind} JSON…</p>}
    {result.error && <p role="alert" className="error">{result.error.message}</p>}
    {data && <div className="technical-panel"><pre tabIndex={0} aria-label={`Batch ${kind} JSON text`}>{data.content}</pre></div>}
  </section>
}
