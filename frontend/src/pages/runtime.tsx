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
    <p className="callout">First pages refresh every 30 seconds while visible. Later pages require manual refresh.
      Worker and queue reads are independent snapshots. Heartbeat does not establish engine health or scan coverage.</p>
    <h2>Worker runtime</h2>
    <p className="muted">Last reported runtime and scan per node; this is not a complete list of concurrent jobs or operating-system processes.</p>
    {workers.isPending && <p role="status">Loading worker runtime…</p>}
    {workers.error && <p role="alert" className="error">{workers.error.message}</p>}
    {!workers.error && workers.data && <>
      <div className="history-table-wrap" role="region" aria-label="Worker runtime table" tabIndex={0}><table className="history-table"><thead><tr>
        <th>Worker</th><th>Heartbeat / lifecycle</th><th>Runtime</th><th>Last reported scan</th></tr></thead><tbody>
        {workers.data.items.map(worker => <tr key={worker.node_id}><td>{worker.display_name}<small>{worker.node_id}</small></td>
          <td>{worker.online ? 'Online' : 'Offline'} / {worker.lifecycle_state}<small>{worker.age_seconds.toLocaleString()} seconds since heartbeat</small></td>
          <td>{worker.runtime_state}</td><td>{worker.active_scan_id === null ? 'None reported' : `#${worker.active_scan_id}`}</td></tr>)}</tbody></table></div>
      {!workers.data.items.length && <p className="empty">No worker nodes on this page.</p>}
      <div className="history-pagination"><Button variant="secondary" disabled={!workerAfter || workers.isFetching} onClick={() => paginate('worker_after', '')}>First workers</Button>
        <Button variant="secondary" disabled={!workers.data.next_after || workers.isFetching} onClick={() => paginate('worker_after', workers.data!.next_after!)}>Next workers</Button></div>
    </>}
    <h2>Active queue</h2><p className="callout">Includes manual, archive-child and automation scans in queued, running or finalizing state.
      Ordered by scan ID, not scheduling priority or queue position. Completed rows disappear; pages can change as workers run.
      Deferred intake that has not yet created a scan is not included.</p>
    {queue.isPending && <p role="status">Loading active queue…</p>}
    {queue.error && <p role="alert" className="error">{queue.error.message}</p>}
    {!queue.error && queue.data && <>
      <div className="history-table-wrap" role="region" aria-label="Active queue table" tabIndex={0}><table className="history-table"><thead><tr>
        <th>Sample</th><th>Source</th><th>Status</th><th>Priority</th><th>Submitted</th></tr></thead><tbody>
        {queue.data.items.map(scan => <tr key={scan.id}><td>{scan.source === 'manual' ? <Link to={`/scans/${scan.id}`}>{scan.filename}</Link> : scan.filename}<small>#{scan.id}</small></td>
          <td>{scan.source}</td><td><span className="health-pill">{scan.status}</span></td><td>{scan.priority}</td><td>{new Date(scan.created_at).toLocaleString()}</td></tr>)}</tbody></table></div>
      {!queue.data.items.length && <p className="empty">No active scans on this page. This does not establish complete coverage or an empty deferred-intake queue.</p>}
      <div className="history-pagination"><Button variant="secondary" disabled={!after || queue.isFetching} onClick={() => paginate('after', '')}>First scans</Button>
        <Button variant="secondary" disabled={!queue.data.next_after || queue.isFetching} onClick={() => paginate('after', String(queue.data!.next_after))}>Next scans</Button></div>
    </>}
  </section>
}
