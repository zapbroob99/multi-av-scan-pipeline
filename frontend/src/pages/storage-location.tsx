import { Fragment, type FormEvent } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import { formatTimestamp, shortAge } from '../lib/utils'
import { STATE_LABELS, STATE_ORDER, formatBytes, locationPath, type LocationDetail } from '../lib/storage'
import { ErrorMessage } from '../components/error-message'
import { BackLink } from '../components/section-tabs'
import { Button } from '../components/ui/button'
import { cycleProblem } from './storage'
import { Timestamp } from '../components/timestamp'

/** A folder's own settings; what happens to each file is its profile's rules. */
function SettingsSummary({ detail }: { detail: LocationDetail }) {
  const settings = detail.policy
  return <dl className="report-metadata">
    <dt>Rules</dt><dd>Each file takes the first rule of the profile <Link to={`/service-clients/${detail.client.id}/profiles`}>{detail.profile.name}</Link> it
      matches. Light check and Block are applied here; a file a Scan rule matches waits for antivirus scanning of folders.</dd>
    <dt>Ignored names</dt><dd>{settings.ignore_patterns?.length ? settings.ignore_patterns.map(item => <code key={item}>{item} </code>) : 'None'}</dd>
    <dt>Timing</dt><dd>Settles after {settings.stability_seconds} s; crawled every {settings.crawl_interval_seconds} s,
      {' '}{settings.crawl_entries_per_cycle?.toLocaleString()} entries and {settings.inspections_per_cycle?.toLocaleString()} inspections per cycle</dd>
  </dl>
}

export default function StorageLocation({ session }: { session: Session }) {
  const locationId = Number(useParams().locationId)
  const [params, setParams] = useSearchParams()
  const valid = Number.isInteger(locationId) && locationId > 0
  const detail = useQuery({ queryKey: ['storage-location', locationId], enabled: valid,
    queryFn: ({ signal }) => request('/api/ui/v1/storage/locations/{location_id}', 'get', { params: { location_id: locationId }, signal }),
    retry: false, staleTime: 0, gcTime: 0, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })
  const query = new URLSearchParams(params)
  query.set('limit', '25')
  const objects = useQuery({ queryKey: ['storage-objects', locationId, query.toString()], enabled: valid,
    queryFn: ({ signal }) => request('/api/ui/v1/storage/locations/{location_id}/objects', 'get', { params: { location_id: locationId }, query, signal }),
    retry: false, staleTime: 0, gcTime: 0, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })

  function filter(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget), next = new URLSearchParams()
    for (const key of ['q', 'state']) {
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
  if (!valid) return <section className="empty"><h1>Location not found</h1></section>
  const data = detail.data
  const problem = data ? cycleProblem(data) : null

  return <section className="page management-page">
    <div className="page-heading"><div><p className="eyebrow">FOLDER SCANNING</p><h1>{data?.name ?? `Location #${locationId}`}</h1>
      {data && <p className="muted"><code>{locationPath(data)}</code> · {data.client.name} · profile {data.profile.name}{data.enabled ? '' : ' · disabled'}</p>}</div>
      <div className="report-actions"><BackLink to="/storage" label="Folders" />
        {session.user.role === 'admin' && data && <Link className="button button-secondary" to={`/storage/locations/${locationId}/edit`}>Edit folder</Link>}
        <Link className="button button-secondary" to={`/storage/findings?location_id=${locationId}`}>Findings</Link>
        <Button variant="secondary" disabled={detail.isFetching || objects.isFetching}
          onClick={() => { void detail.refetch(); void objects.refetch() }}>Refresh</Button></div></div>
    {detail.isPending && <p role="status">Loading location…</p>}
    {detail.error && <p role="alert" className="error"><ErrorMessage message={detail.error.message || ''} /></p>}
    {data && <>
      {!data.enabled && <p className="notice">This folder is disabled. Its inventory and findings are kept; nothing is crawled or inspected.</p>}
      {problem && <p className="notice error" role="alert">{problem}</p>}
      {data.policy_invalid && <p className="notice error" role="alert">The stored folder settings could not be read. The worker skips this folder
        until an administrator saves valid settings; the values below are defaults, not the stored settings.</p>}
      <article className="submission-card" aria-label="Coverage">
        <h2>Coverage</h2>
        <dl className="report-metadata">
          {STATE_ORDER.map(state => <Fragment key={state}><dt>{STATE_LABELS[state]}</dt>
            <dd>{(data.counts[state] ?? 0).toLocaleString()}</dd></Fragment>)}
          <dt>Detected findings</dt><dd>{data.detected_findings.toLocaleString()}</dd>
          <dt>Last cycle</dt><dd>{data.last_cycle ? `${formatTimestamp(data.last_cycle.at)} (${shortAge(data.last_cycle.age_seconds)} ago): `
            + `${data.last_cycle.crawled.toLocaleString()} entries read, ${data.last_cycle.inspected.toLocaleString()} inspected, `
            + `${data.last_cycle.findings.toLocaleString()} new finding(s)` : 'Never'}</dd>
          <dt>Current crawl</dt><dd>{data.current_pass ? `Started ${formatTimestamp(data.current_pass.started_at)}; `
            + `${data.current_pass.objects_seen.toLocaleString()} files seen so far` : 'None running'}</dd>
          <dt>Last complete crawl</dt><dd>{data.last_completed_pass ? `${formatTimestamp(data.last_completed_pass.finished_at)}: `
            + `${data.last_completed_pass.objects_seen.toLocaleString()} files, ${data.last_completed_pass.objects_new.toLocaleString()} new, `
            + `${data.last_completed_pass.objects_changed.toLocaleString()} changed, ${data.last_completed_pass.objects_removed.toLocaleString()} removed`
            : 'No crawl has read the whole location yet'}</dd>
        </dl>
        <p className="muted">Counts cover the whole inventory. "{STATE_LABELS.light_passed}" means the rule's light checks found nothing;
          it is not a clean antivirus result.</p>
      </article>
      <article className="submission-card" aria-label="Rules and settings">
        <h2>Rules and settings <small className="muted">settings revision {data.policy_revision}</small></h2>
        <SettingsSummary detail={data} />
        <p className="muted">A rule or settings change applies to files inspected afterwards. Files already inspected are judged again only
          when they change.</p>
      </article>
    </>}

    <form key={params.toString()} onSubmit={filter} className="submission-card" aria-label="File filters"><fieldset className="history-filters">
      <label>Path contains<input name="q" maxLength={200} defaultValue={params.get('q') || ''} /></label>
      <label>State<select name="state" defaultValue={params.get('state') || 'all'}>
        <option value="all">all</option>{STATE_ORDER.map(state => <option key={state} value={state}>{STATE_LABELS[state]}</option>)}</select></label>
      <Button type="submit" disabled={objects.isFetching}>Apply filters</Button>
      <Button type="button" variant="secondary" onClick={() => setParams({})}>Reset filters</Button>
    </fieldset><p className="muted">Newest files first. <code>%</code> and <code>_</code> match themselves.</p></form>
    {objects.isPending && <p role="status">Loading files…</p>}
    {objects.error && <p role="alert" className="error"><ErrorMessage message={objects.error.message || ''} /></p>}
    {objects.data && <>
      {!objects.data.items.length && <p className="empty">No files match these filters.</p>}
      {objects.data.items.length > 0 && <div className="history-table-wrap" role="region" aria-label="Files" tabIndex={0}>
        <table className="history-table compact-table"><thead><tr>
          <th scope="col">File</th><th scope="col">State</th><th scope="col">Content</th><th scope="col">Size</th><th scope="col">Changed</th>
        </tr></thead><tbody>
        {objects.data.items.map(item => <tr key={item.id} className={item.state === 'light_detected' ? 'row-alert' : ''}>
          <td className="cell-name" title={item.object_id}><code>{item.object_id}</code>
            {item.sha256 && <small className="hash-value">{item.sha256}</small>}</td>
          <td>{STATE_LABELS[item.state]}{item.finding_count > 0 && <small>{item.finding_count} finding(s)</small>}
            {item.last_error && <small className="error">{item.last_error}</small>}</td>
          <td><small>{item.detected_type || 'unrecognized'}</small><small>{item.families.join(', ')}</small>
            {item.hash_list_kind && <small>hash {item.hash_list_kind}listed</small>}</td>
          <td><small>{formatBytes(item.size_bytes)}</small></td>
          <td><small><Timestamp value={item.last_changed_at} /></small>
            {item.processed_at && <small>inspected <Timestamp value={item.processed_at} /></small>}</td>
        </tr>)}</tbody></table></div>}
      {Boolean(params.get('before') || objects.data.next_before) && <div className="history-pagination">
        <Button variant="secondary" disabled={objects.isFetching || !params.get('before')} onClick={() => paginate()}>Newest files</Button>
        <Button variant="secondary" disabled={objects.isFetching || !objects.data.next_before} onClick={() => paginate(objects.data!.next_before!)}>Older files</Button></div>}
    </>}
  </section>
}
