import { type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { request } from '../lib/api'
import { formatTimestamp } from '../lib/utils'
import { KIND_LABELS, STATE_LABELS, type StorageFinding } from '../lib/storage'
import { ErrorMessage } from '../components/error-message'
import { Button } from '../components/ui/button'

const KINDS = Object.keys(KIND_LABELS) as StorageFinding['kind'][]

export default function StorageFindings() {
  const [params, setParams] = useSearchParams()
  const query = new URLSearchParams(params)
  query.set('limit', '25')
  const findings = useQuery({ queryKey: ['storage-findings', query.toString()],
    queryFn: ({ signal }) => request('/api/ui/v1/storage/findings', 'get', { query, signal }),
    retry: false, staleTime: 0, gcTime: 0, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })

  function filter(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget), next = new URLSearchParams()
    for (const key of ['kind', 'detected', 'location_id']) {
      const value = String(form.get(key) || '').trim()
      if (value && value !== 'all') next.set(key, value)
    }
    setParams(next)
  }
  function paginate(before?: number) {
    const next = new URLSearchParams(params)
    if (before) next.set('before', String(before)); else next.delete('before')
    setParams(next)
  }

  return <section className="page management-page">
    <div className="page-heading"><div><p className="eyebrow">FOLDER SCANNING</p><h1>Findings</h1>
      <p className="muted">What the light tier found in protected locations, newest first.</p></div>
      <Button variant="secondary" disabled={findings.isFetching} onClick={() => { void findings.refetch() }}>Refresh</Button></div>
    <p className="muted">A detected finding with high severity is also sent to SIEM when notification delivery is deployed. A finding that is not
      a detection (for example a disguised image) is recorded for review only. MASP never quarantines or modifies the file.</p>
    <form key={params.toString()} onSubmit={filter} className="submission-card" aria-label="Finding filters"><fieldset className="history-filters">
      <label>Kind<select name="kind" defaultValue={params.get('kind') || 'all'}>
        <option value="all">all</option>{KINDS.map(kind => <option key={kind} value={kind}>{KIND_LABELS[kind]}</option>)}</select></label>
      <label>Outcome<select name="detected" defaultValue={params.get('detected') || 'all'}>
        <option value="all">all</option><option value="detected">detections</option><option value="not_detected">review only</option></select></label>
      <label>Location ID<input name="location_id" inputMode="numeric" pattern="[0-9]*" maxLength={16} defaultValue={params.get('location_id') || ''} /></label>
      <Button type="submit" disabled={findings.isFetching}>Apply filters</Button>
      <Button type="button" variant="secondary" onClick={() => setParams({})}>Reset filters</Button>
    </fieldset></form>
    {findings.isPending && <p role="status">Loading findings…</p>}
    {findings.error && <p role="alert" className="error"><ErrorMessage message={findings.error.message || ''} /></p>}
    {findings.data && <>
      {!findings.data.items.length && <p className="empty">No findings match these filters.</p>}
      {findings.data.items.length > 0 && <div className="history-table-wrap" role="region" aria-label="Findings" tabIndex={0}>
        <table className="history-table compact-table"><thead><tr>
          <th scope="col">File</th><th scope="col">Finding</th><th scope="col">Severity</th><th scope="col">Location</th><th scope="col">Found</th>
        </tr></thead><tbody>
        {findings.data.items.map(item => <tr key={item.id} className={item.detected ? 'row-alert' : ''}>
          <td className="cell-name" title={item.object_id}><code>{item.object_id}</code>
            {item.sha256 && <small className="hash-value">{item.sha256}</small>}
            {item.object_state && <small>Now: {STATE_LABELS[item.object_state]}</small>}</td>
          <td>{KIND_LABELS[item.kind]}<small>{item.title}</small></td>
          <td>{item.severity}<small>{item.detected ? 'detection' : 'review only'}</small></td>
          <td className="cell-name"><Link to={`/storage/locations/${item.location.id}`}>{item.location.name}</Link>
            <small>policy revision {item.policy_revision}</small></td>
          <td><small>{formatTimestamp(item.created_at)}</small></td>
        </tr>)}</tbody></table></div>}
      {Boolean(params.get('before') || findings.data.next_before) && <div className="history-pagination">
        <Button variant="secondary" disabled={findings.isFetching || !params.get('before')} onClick={() => paginate()}>Newest findings</Button>
        <Button variant="secondary" disabled={findings.isFetching || !findings.data.next_before} onClick={() => paginate(findings.data!.next_before!)}>Older findings</Button></div>}
    </>}
  </section>
}
