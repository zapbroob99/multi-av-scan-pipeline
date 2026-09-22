import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { request } from '../lib/api'
import { Button } from '../components/ui/button'

export default function SystemOverview() {
  const [params, setParams] = useSearchParams()
  const after = params.get('after') || ''
  const [showMetrics, setShowMetrics] = useState(Boolean(after))
  const summary = useQuery({ queryKey: ['system-summary'], queryFn: ({ signal }) => request('/api/ui/v1/system/summary', 'get', { signal }),
    retry: false, gcTime: 60000, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })
  const metrics = useQuery({ queryKey: ['system-engine-metrics', after], enabled: showMetrics,
    queryFn: ({ signal }) => request('/api/ui/v1/system/engine-metrics', 'get', {
      query: new URLSearchParams({ limit: '20', ...(after ? { after } : {}) }), signal }),
    retry: false, gcTime: 60000, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })
  return <section className="page management-page"><div className="page-heading"><div><p className="eyebrow">SYSTEM</p><h1>System overview</h1>
    <p className="muted">Recorded scan totals, worker liveness and historical result statistics.</p></div>
    <Button variant="secondary" disabled={summary.isFetching} onClick={() => { void summary.refetch() }}>Refresh overview</Button></div>
    <nav className="report-actions" aria-label="System sections"><Link to="/system">Manage worker nodes</Link><Link to="/system/pools">Worker pools</Link>
      <Link to="/system/runtime">Runtime and active queue</Link><Link to="/engines">Engine health and placement</Link></nav>
    <p className="callout">Totals include all scan sources and archive children. Counts can be cached for 30 seconds.
      Completion and detections are recorded outcomes, not proof of complete coverage or a policy allow decision.</p>
    {summary.isPending && <p role="status">Loading system overview…</p>}
    {summary.error && <p role="alert" className="error">{summary.error.message}</p>}
    {!summary.error && summary.data && <>
      <div className="stats-row dashboard-stats">{(['total', 'queued', 'running', 'finalizing', 'completed', 'failed'] as const).map(key =>
        <div key={key}><span>{key}</span><strong>{summary.data![key].toLocaleString()}</strong></div>)}</div>
      <section className="submission-card"><h2>Worker liveness</h2><dl className="report-metadata">
        <dt>Registered nodes</dt><dd>{summary.data.registered_nodes}</dd><dt>Online nodes</dt><dd>{summary.data.online_nodes}</dd>
        <dt>Online and active</dt><dd>{summary.data.active_online_nodes}</dd></dl>
        <p className="muted">Online and active nodes may still lack capacity, matching adapters or eligible pool assignments. Check engine health before relying on coverage.</p></section>
      <section className="submission-card"><h2>Retention policy</h2><p>{summary.data.retention_days > 0
        ? `Enabled: ${summary.data.retention_days} days; configured batch limit ${summary.data.retention_batch_size}. Console runs are capped at 20 records.` : 'Retention cleanup is disabled.'}</p>
        <p className="muted">Policy is configured on the server. Viewing this page does not delete data.</p>
        <Link to="/system/retention">Review retention cleanup</Link></section>
      <p className="muted">Overview generated {new Date(summary.data.generated_at).toLocaleString()}</p>
    </>}
    <div className="history-heading"><div><h2>Historical engine metrics</h2><p className="muted">Statistics by the engine name recorded on retained results.</p></div>
      <Button variant="secondary" disabled={metrics.isFetching} onClick={() => { if (showMetrics) { void metrics.refetch() } else setShowMetrics(true) }}>
        {showMetrics ? 'Refresh engine metrics' : 'Load engine metrics'}</Button></div>
    <p className="callout">Metrics include retained results across all sources, including historical engine names. A name is not a stable deployment identity:
      renames split history and reused names can combine it. Latency is recorded engine duration, not end-to-end scan latency.
      Retries and retention can remove results; pages are not a frozen history. No automatic polling.</p>
    {showMetrics && metrics.isPending && <p role="status">Loading historical metrics…</p>}
    {metrics.error && <p role="alert" className="error">{metrics.error.message}</p>}
    {showMetrics && !metrics.error && metrics.data && <>
      <div className="history-table-wrap" role="region" aria-label="Historical engine metrics" tabIndex={0}><table className="history-table"><thead><tr>
        <th>Recorded engine name</th><th>Total</th><th>Completed</th><th>Failed</th><th>Skipped</th><th>Detections</th><th>Avg / max duration</th></tr></thead><tbody>
        {metrics.data.items.map(metric => <tr key={metric.first_result_id}><td>{metric.engine_name}{metric.name_truncated && <small>Name truncated</small>}</td>
          <td>{metric.total}</td><td>{metric.completed}</td><td>{metric.failed}</td><td>{metric.skipped}</td><td>{metric.detections}</td>
          <td>{metric.avg_duration_ms === null ? 'Unknown' : `${metric.avg_duration_ms.toFixed(1)} ms`} / {metric.max_duration_ms === null ? 'Unknown' : `${metric.max_duration_ms} ms`}</td></tr>)}</tbody></table></div>
      {!metrics.data.items.length && <p className="empty">No recorded engine results on this page.</p>}
      <p className="muted">Metrics generated {new Date(metrics.data.generated_at).toLocaleString()}; cached for up to 30 seconds.</p>
      <div className="history-pagination"><Button variant="secondary" disabled={!after || metrics.isFetching} onClick={() => setParams({})}>First engine names</Button>
        <Button variant="secondary" disabled={!metrics.data.next_after || metrics.isFetching} onClick={() => setParams({ after: String(metrics.data!.next_after) })}>Next engine names</Button></div>
    </>}
  </section>
}
