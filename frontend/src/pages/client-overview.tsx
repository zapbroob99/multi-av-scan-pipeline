import { useContext, useEffect, useId, useRef, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import { formatBytes } from '../lib/storage'
import { Button } from '../components/ui/button'
import { ClientWorkspace, ClientPanelLink } from '../components/client-workspace'
import { ClientNavigation } from '../components/client-navigation'
import { ErrorMessage } from '../components/error-message'
import { Timestamp } from '../components/timestamp'
import { conditionText } from '../components/profile-rules'
import { ConfigurationContext } from '../components/configuration-context'
import { RulePreview } from '../components/rule-preview'

export default function ClientOverview({ session }: { session: Session }) {
  const selectorId = useId()
  const workspace = useContext(ClientWorkspace)
  const params = useParams()
  const [searchParams] = useSearchParams()
  const id = workspace?.clientId ?? Number(params.clientId)
  const valid = Number.isSafeInteger(id) && id > 0
  const [source, setSource] = useState<'api' | 'icap'>('api')
  const [profileId, setProfileId] = useState(() => workspace ? '' : searchParams.get('profile_id') || '')
  const [after, setAfter] = useState('')
  const view = useQuery({ queryKey: ['client-configuration', id, profileId], enabled: valid,
    queryFn: ({ signal }) => request('/api/ui/v1/service-clients/{client_id}/configuration', 'get', {
      params: { client_id: id }, query: new URLSearchParams(profileId ? { profile_id: profileId } : {}), signal }),
    retry: false, gcTime: 0, staleTime: 0, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })
  const profiles = useQuery({ queryKey: ['overview-profiles', id, after], enabled: valid,
    queryFn: ({ signal }) => request('/api/ui/v1/service-clients/{client_id}/profiles', 'get', {
      params: { client_id: id }, query: new URLSearchParams(after ? { after } : {}), signal }),
    retry: false, gcTime: 0, refetchOnWindowFocus: false, refetchOnReconnect: false })
  const connection = useQuery({ queryKey: ['overview-readiness', id], enabled: valid,
    queryFn: ({ signal }) => request('/api/ui/v1/service-clients/{client_id}/readiness', 'get', { params: { client_id: id }, signal }),
    retry: false, gcTime: 0, refetchOnWindowFocus: false, refetchOnReconnect: false })
  const active = !workspace || workspace.tab === 'overview'
  const previousActive = useRef(active)
  useEffect(() => {
    if (active && !previousActive.current) { void view.refetch(); void profiles.refetch(); void connection.refetch() }
    previousActive.current = active
  }, [active, view.refetch, profiles.refetch, connection.refetch])
  const data = !view.error && !view.isFetching ? view.data : undefined
  const method = !connection.error && !connection.isFetching ? connection.data?.methods.find(item => item.key === source) : undefined
  const choices = profiles.data?.items ?? []
  const profile = data?.profile
  const engineName = (engineId: number) => data?.engines.find(engine => engine.id === engineId)?.name ?? `Engine #${engineId}`
  if (!valid) return <section className="page"><h1>Invalid client ID</h1></section>
  return <section className="page management-page client-page">
    <ClientNavigation clientId={id} />
    <div className="page-heading"><div><h1>Configuration overview</h1><p className="muted">Follow this client's submission path. Open the relevant editor from each step.</p></div>
      <Button variant="secondary" disabled={view.isFetching || profiles.isFetching || connection.isFetching} onClick={() => {
        void view.refetch(); void profiles.refetch(); void connection.refetch()
      }}>Refresh overview</Button></div>
    <div className="configuration-selectors">
      <div><label htmlFor={`${selectorId}-source`}>Submission path</label><select id={`${selectorId}-source`} value={source} onChange={event => { setSource(event.target.value as 'api' | 'icap'); setProfileId('') }}>
        <option value="api">REST API upload</option><option value="icap">ICAP gateway</option></select></div>
      <div><label htmlFor={`${selectorId}-profile`}>Profile</label><select id={`${selectorId}-profile`} value={profileId} disabled={source === 'icap' || profiles.isFetching || !!profiles.error} onChange={event => setProfileId(event.target.value)}>
        <option value="">Current default profile</option>
        {profileId && !choices.some(item => String(item.id) === profileId) && <option value={profileId}>{profile?.name ?? `Profile #${profileId}`}</option>}
        {choices.map(item => <option key={item.id} value={item.id}>{item.name}{item.enabled ? '' : ' (disabled)'}</option>)}</select></div>
    </div>
    {source === 'icap' && <p className="muted">ICAP always uses this client's default profile. Named profiles can be selected for REST API requests.</p>}
    {profiles.error && <p role="alert" className="error"><ErrorMessage message={profiles.error.message} /></p>}
    {(after || profiles.data?.next_after) && <div className="report-actions">
      <Button variant="secondary" disabled={!after || profiles.isFetching} onClick={() => setAfter('')}>First profiles</Button>
      <Button variant="secondary" disabled={!profiles.data?.next_after || profiles.isFetching} onClick={() => setAfter(String(profiles.data!.next_after))}>Next profiles</Button></div>}
    {view.isFetching && <p role="status">Reading configuration…</p>}
    {view.error && <p role="alert" className="error"><ErrorMessage message={view.error.message} /></p>}
    {data && <>
      <p className="muted">Configuration read <Timestamp value={new Date(data.observed_at * 1000).toISOString()} />. Current settings explain new submissions; accepted scans keep their recorded routing.</p>
      <ol className="configuration-steps">
        <li><section className="settings-panel"><div className="settings-panel-header"><h2>1. Connection</h2>
          <ClientPanelLink clientId={id} tab="setup">Connection details</ClientPanelLink></div><div className="settings-panel-body">
          <p><strong>{data.client_name}</strong> · {data.enabled ? 'Client enabled' : 'Client disabled — new submissions refused'}</p>
          {connection.error && <p role="alert" className="error"><ErrorMessage message={connection.error.message} /></p>}
          {connection.isFetching ? <p role="status">Reading connection state…</p> : method ? <p>{method.label}: {method.summary}</p> : <p>Connection state unknown.</p>}
          <p className="muted">Connection evidence is read separately. It does not prove network access, valid token possession or engine health.</p>
          <ClientPanelLink clientId={id} tab="credentials">Manage API credentials</ClientPanelLink>
        </div></section></li>
        <li><section className="settings-panel"><div className="settings-panel-header"><h2>2. Profile and file rules</h2>
          <ClientPanelLink clientId={id} tab="profiles">Edit profiles and rules</ClientPanelLink></div><div className="settings-panel-body">
          <ConfigurationContext context={data.profile_context} />
          {profile ? <><p><strong>{profile.name}</strong> · revision {profile.management_revision} · {profile.enabled ? 'Enabled' : 'Disabled — cannot accept new routing'}</p>
            {(profile.incomplete || data.managed) && <p className="callout">{data.managed ? 'Deployment-managed compatibility routing. This view does not reconstruct its effective policy.' : 'Profile data is incomplete. This is not a complete routing explanation.'}</p>}
            {profile.rules && !profile.incomplete && !data.managed ? <><p className="muted">The first matching rule applies. This is the rule list, not a verdict for a particular file.</p>
              <div className="history-table-wrap"><table className="history-table"><thead><tr><th>When</th><th>Action</th><th>Engines</th></tr></thead>
                <tbody>{profile.rules.rules.map((rule, index) => <tr key={index}><td>{conditionText(rule, index === profile.rules!.rules.length - 1)}</td>
                  <td>{{ scan: 'Scan', light: 'Light check', allow: 'Allow without scanning', block: 'Block' }[rule.action]}
                    {rule.archive && <small>Archives: {{ whole: 'scan as one file', inspect: 'open and check', members: 'scan every member' }[rule.archive]}</small>}</td>
                  <td>{(rule.engines ?? []).length ? (rule.engines ?? []).map(engineName).join(', ') : 'None'}</td></tr>)}</tbody></table></div>
              <p>Inconclusive results: <strong>{profile.rules.inconclusive === 'block' ? 'Block' : 'Allow, labelled Not fully scanned'}</strong>.</p>
              {active && <RulePreview key={`${profile.id}:${profile.management_revision}:${source}`} configuration={data} source={source} session={session} />}</>
              : !data.managed && <p role="alert">Rules are unavailable. No allow decision can be inferred.</p>}</>
            : <p role="alert">No default profile exists. Open profiles to configure routing.</p>}
        </div></section></li>
        <li><section className="settings-panel"><div className="settings-panel-header"><h2>3. Limits before the rules</h2>
          <Link to={source === 'api' ? '/scan-policy' : '/integrations/gateways'}>{source === 'api' ? 'Edit upload policy' : 'Inspect ICAP gateways'}</Link></div><div className="settings-panel-body">
          {source === 'api' ? <dl className="report-metadata"><dt>File size policy</dt><dd>{data.upload_policy_bytes ? formatBytes(data.upload_policy_bytes) : 'No limit at this layer'}<small>{data.upload_policy_source} · changes apply to new requests</small></dd>
            <dt>HTTP request body ceiling</dt><dd>{data.http_configuration_valid && data.http_body_ceiling_bytes != null ? formatBytes(data.http_body_ceiling_bytes) : 'Invalid configuration — uploads refused'}
              <small>API process environment · MASP_HTTP_UPLOAD_MAX_BYTES · deployment change requires service recreation/restart</small></dd>
            <dt>How they combine</dt><dd>The request must fit the body ceiling, including multipart overhead. A file policy of 0 does not remove this ceiling. External proxy limits are not observed here.</dd></dl>
            : <>{!data.gateways.length && <p>No gateway report for this client. ICAP limits are unknown.</p>}
              {data.gateways.map((gateway, index) => <div key={`${gateway.port}-${index}`} className="configuration-gateway"><p><strong>Port {gateway.port}</strong> · {gateway.stale ? 'Report stale — current settings unknown' : 'Last reported settings'}</p>
                <p>Size: {gateway.max_bytes == null ? 'unknown' : gateway.max_bytes === 0 ? 'no limit reported' : formatBytes(gateway.max_bytes)} · wait: {gateway.wait_seconds == null ? 'unknown' : `${gateway.wait_seconds} s`}.</p>
                <p>Oversize, unreachable MASP or no verdict in time: <strong>{gateway.fail_closed == null ? 'Unknown — not reported' : gateway.fail_closed ? 'Block' : 'Allow without scanning'}</strong>.</p>
                <p className="muted">Gateway report <Timestamp value={new Date(gateway.reported_at * 1000).toISOString()} />. Startup configuration; change the gateway deployment and restart it.</p></div>)}
              {data.gateways_incomplete && <p role="alert">Gateway inventory exceeds the read limit; this list may be incomplete.</p>}</>}
          <p className="muted">Admission is not scanning coverage. Engine and archive limits may still prevent a complete scan after acceptance.</p>
          {source === 'api' && <><ConfigurationContext context={data.upload_policy_context} title="File policy scope and application" />
            <ConfigurationContext context={data.http_context} title="HTTP ceiling scope and application" /></>}
        </div></section></li>
        <li><section className="settings-panel"><div className="settings-panel-header"><h2>4. Engines and worker evidence</h2><Link to="/engines">Manage engines and health</Link></div><div className="settings-panel-body">
          <ConfigurationContext context={data.placement_context} />
          <p className="muted">Engines below are used by this profile's rules; a file runs only its matched rule's engines. Worker observations are historical, may belong to previous placement, and do not establish current scheduler eligibility or capacity.</p>
          {!data.engines.length && <p>No engine assignments.</p>}
          {data.engines.map(engine => <article className="configuration-engine" key={engine.id}><h3>{engine.name}</h3>
            <p>{engine.eligible ? 'Eligible for API/ICAP by configuration' : engine.excluded_reason}</p>
            <p>{engine.pool_id == null ? 'Placement: any compatible worker' : `Placement: ${engine.pool_name ?? 'missing pool'}${engine.pool_enabled ? '' : ' — disabled or unavailable'}`}</p>
            {!engine.observations.length && <p>No worker check recorded. Execution is not verified here.</p>}
            {engine.observations.length > 0 && <details><summary>Recorded worker checks ({engine.observations.length})</summary>
              {engine.observations.map(worker => <p key={worker.node_id}><code>{worker.node_id}</code> · {worker.online ? 'recent heartbeat' : 'heartbeat stale'} · {worker.lifecycle} · check: {worker.check}
                {worker.checked_at != null && <> · <Timestamp value={new Date(worker.checked_at * 1000).toISOString()} /></>}</p>)}</details>}
            {engine.observations_incomplete && <p>Worker evidence is incomplete. Inspect engine health for current placement.</p>}</article>)}
          <Link to="/system">Inspect worker nodes</Link> · <Link to="/system/pools">Manage worker pools</Link>
        </div></section></li>
      </ol>
    </>}
  </section>
}
