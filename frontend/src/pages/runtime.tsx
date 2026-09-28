import { ErrorMessage } from '../components/error-message'
import { formatTimestamp, heartbeatLabel } from '../lib/utils'
import { HelpDetails } from '../components/help-details'
import { Link, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { request } from '../lib/api'
import { Button } from '../components/ui/button'

export default function Runtime() {
  const [params, setParams] = useSearchParams()
  const after = params.get('after') || ''
  const workerAfter = params.get('worker_after') || ''
  const queue = useQuery({ queryKey: ['system-queue', after], queryFn: ({ signal }) => request('/api/ui/v1/system/queue', 'get', {
    query: new URLSearchParams({ limit: '20', ...(after ? { after } : {}) }), signal }),
    retry: false, gcTime: 60000, refetchOnMount: 'always', refetchOnWindowFocus: false,
    refetchInterval: after ? false : 30000, refetchIntervalInBackground: false })
  const workers = useQuery({ queryKey: ['system-workers', workerAfter], queryFn: ({ signal }) => request('/api/ui/v1/system/workers', 'get', {
    query: new URLSearchParams({ limit: '20', ...(workerAfter ? { after: workerAfter } : {}) }), signal }),
    retry: false, gcTime: 60000, refetchOnMount: 'always', refetchOnWindowFocus: false,
    refetchInterval: workerAfter ? false : 30000, refetchIntervalInBackground: false })
  function paginate(key: string, value: string) {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value); else next.delete(key)
    setParams(next)
  }
  return <section className="page"><div className="page-heading"><div><p className="eyebrow">SYSTEM</p><h1>Runtime and active queue</h1>
    <p className="muted">Recorded worker activity and accepted scans still in progress.</p></div>
    <Button variant="secondary" disabled={queue.isFetching || workers.isFetching} onClick={() => { void queue.refetch(); void workers.refetch() }}>Refresh runtime</Button></div>
    <p className="muted">First pages refresh every 30 seconds. Open a worker or scan to investigate.</p>
    <HelpDetails title="About runtime updates">Later pages require manual refresh.
      Worker and queue reads are independent snapshots. Heartbeat does not establish engine health or scan coverage.</HelpDetails>
    <h2>Worker runtime</h2>
    <p className="muted">Last reported runtime and scan per node; this is not a complete list of concurrent jobs or operating-system processes.</p>
    {workers.isPending && <p role="status">Loading worker runtime…</p>}
    {workers.error && <p role="alert" className="error"><ErrorMessage message={workers.error.message || ''} /></p>}
    {!workers.error && workers.data && <>
      <div className="history-table-wrap" role="region" aria-label="Worker runtime table" tabIndex={0}><table className="history-table"><thead><tr>
        <th>Worker</th><th>Heartbeat / lifecycle</th><th>Runtime</th><th>Last reported scan</th></tr></thead><tbody>
        {workers.data.items.map(worker => <tr key={worker.node_id}><td><Link to={`/system?${new URLSearchParams({ node: worker.node_id, ...(workerAfter ? { after: workerAfter } : {}) })}`}>{worker.display_name}</Link><small>{worker.node_id}</small></td>
          <td>{worker.online ? 'Online' : 'Offline'} / {worker.lifecycle_state}<small>{heartbeatLabel(worker.last_heartbeat_at, worker.age_seconds)}</small></td>
          <td>{worker.runtime_state}</td><td>{worker.active_scan_id === null ? 'None reported' : <a href={`/scans/${worker.active_scan_id}`}>Scan #{worker.active_scan_id}</a>}</td></tr>)}</tbody></table></div>
      {!workers.data.items.length && <p className="empty">No worker nodes on this page.</p>}
      {(workerAfter || workers.data.next_after) && <div className="history-pagination"><Button variant="secondary" disabled={!workerAfter || workers.isFetching} onClick={() => paginate('worker_after', '')}>First workers</Button>
        <Button variant="secondary" disabled={!workers.data.next_after || workers.isFetching} onClick={() => paginate('worker_after', workers.data!.next_after!)}>Next workers</Button></div>}
    </>}
    <h2>Active queue</h2><p className="muted">Manual and automation scans in progress. <Link to="/system/intake">Check files waiting for intake</Link>.</p>
    <HelpDetails title="What the active queue includes">Includes archive children and scans in queued, running or finalizing state.
      Ordered by scan ID, not scheduling priority or queue position. Completed rows disappear; pages can change as workers run.
      Deferred intake that has not yet created a scan is not included.</HelpDetails>
    {queue.isPending && <p role="status">Loading active queue…</p>}
    {queue.error && <p role="alert" className="error"><ErrorMessage message={queue.error.message || ''} /></p>}
    {!queue.error && queue.data && <>
      <div className="history-table-wrap" role="region" aria-label="Active queue table" tabIndex={0}><table className="history-table"><thead><tr>
        <th>Sample</th><th>Source</th><th>Status</th><th>Priority</th><th>Submitted</th></tr></thead><tbody>
        {queue.data.items.map(scan => <tr key={scan.id}><td>{['manual', 'api', 'icap'].includes(scan.source)
          ? <Link to={`${scan.source === 'manual' ? '' : '/api-ledger'}/scans/${scan.id}`}>{scan.filename}</Link>
          : <a href={`/scans/${scan.id}`}>{scan.filename}</a>}<small>#{scan.id}</small></td>
          <td>{scan.source}</td><td><span className="health-pill">{scan.status}</span></td><td>{scan.priority}</td><td>{formatTimestamp(scan.created_at)}</td></tr>)}</tbody></table></div>
      {!queue.data.items.length && <p className="empty">No active scans on this page. This does not establish complete coverage or an empty deferred-intake queue.</p>}
      {(after || queue.data.next_after) && <div className="history-pagination"><Button variant="secondary" disabled={!after || queue.isFetching} onClick={() => paginate('after', '')}>First scans</Button>
        <Button variant="secondary" disabled={!queue.data.next_after || queue.isFetching} onClick={() => paginate('after', String(queue.data!.next_after))}>Next scans</Button></div>}
    </>}
  </section>
}
