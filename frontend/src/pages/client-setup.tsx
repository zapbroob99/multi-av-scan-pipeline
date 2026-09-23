import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ArrowRight, CheckCircle2, CircleAlert, RefreshCw } from 'lucide-react'
import { request } from '../lib/api'
import { Button } from '../components/ui/button'
import { ClientNavigation } from '../components/client-navigation'
import { useContext } from 'react'
import { ClientWorkspace, ClientPanelLink } from '../components/client-workspace'

export default function ClientSetup() {
  const params = useParams()
  const workspace = useContext(ClientWorkspace)
  const clientId = String(workspace?.clientId ?? params.clientId ?? '')
  const valid = /^\d+$/.test(clientId) && Number.isSafeInteger(Number(clientId)) && Number(clientId) > 0
  const setup = useQuery({ queryKey: ['client-readiness', clientId], enabled: valid,
    queryFn: ({ signal }) => request('/api/ui/v1/service-clients/{client_id}/readiness', 'get', {
      params: { client_id: Number(clientId) }, signal }),
    staleTime: 0, gcTime: 0, retry: false, refetchOnMount: 'always',
    refetchOnWindowFocus: false, refetchOnReconnect: false, refetchInterval: false })
  if (!valid) return <section className="page"><h1>Invalid client ID</h1><Link to="/service-clients">Service clients</Link></section>
  const data = !setup.error && !setup.isFetching ? setup.data : undefined
  const blocking = data?.checks.filter(check => !check.passed) ?? []
  return <section className="page management-page client-page"><ClientNavigation clientId={clientId} /><div className="page-heading"><div><p className="eyebrow">CLIENT CONNECTION · #{clientId}</p>
    <h1>Connect a client</h1><p className="muted">Configuration readiness and the values the other system needs.</p></div>
    <Button variant="secondary" disabled={setup.isFetching} onClick={() => { void setup.refetch() }}><RefreshCw size={14} aria-hidden="true" />Refresh readiness</Button></div>
    {setup.isFetching && <p role="status">Loading client readiness…</p>}
    {setup.error && <p role="alert" className="error">{setup.error.message}</p>}
    {data && <>
      <div className="client-setup-grid"><section className="submission-card" aria-label="Readiness">
        <div className="client-section-heading"><div><p className="eyebrow">CONFIGURATION CHECKLIST</p><h2>{data.display_name}</h2><p className="muted client-key"><code>{data.client_key}</code></p></div>
          <span className="client-badge">{data.checks.filter(check => check.passed).length} / {data.checks.length} checks</span></div>
        <p className={data.ready ? 'callout' : 'error'} role={data.ready ? undefined : 'alert'}>
          {data.ready
            ? 'Configuration is complete. This does not prove the integration can reach MASP or that its token is correct.'
            : `Not ready: ${blocking.length} item(s) still need attention.`}</p>
        <ul className="client-checklist">{data.checks.map(check => <li key={check.key} className={check.passed ? 'client-check-pass' : 'client-check-fail'}>
          {check.passed ? <CheckCircle2 size={18} aria-hidden="true" /> : <CircleAlert size={18} aria-hidden="true" />}
          <div><strong>{check.label}</strong><span className="muted">{check.detail}</span>
            {!check.passed && <ClientPanelLink clientId={clientId} tab={check.key === 'client_enabled' ? 'settings' : check.key === 'active_credential' ? 'credentials' : 'profiles'}>
              {check.key === 'client_enabled' ? 'Review client settings' : check.key === 'active_credential' ? 'Manage credentials' : 'Review profile routing'}<ArrowRight size={12} aria-hidden="true" /></ClientPanelLink>}</div>
          <span className="client-check-status">{check.passed ? 'Ready' : 'Action needed'}</span></li>)}</ul>
        {data.managed && <p className="callout">Managed compatibility client. Its routing follows deployment configuration rather than this profile.</p>}
      </section>

      <section className="submission-card" aria-label="Connection details">
        <p className="eyebrow">INTEGRATION REFERENCE</p><h2>Point the other system here</h2>
        <dl className="client-endpoints">
          <div><dt>Submit a file</dt><dd><code>POST {data.scan_endpoint}</code></dd></div>
          <div><dt>Poll a scan</dt><dd><code>GET {data.status_endpoint}</code></dd></div>
          <div><dt>Large-file intake</dt><dd><code>POST {data.deferred_endpoint}</code></dd></div>
          <div><dt>Authentication</dt><dd><code>{data.authorization_header}</code></dd></div>
          <div><dt>ICAP gateway</dt><dd><code>{data.icap_client_key_setting}</code></dd></div>
        </dl>
        <p className="muted client-note">A credential value is never shown after it is saved; MASP stores only its hash. Issue a new
          credential if the integration no longer has its token. An ICAP gateway carries no bearer token: bind a dedicated
          listener to this client key instead, and keep the host firewall authoritative for source control.</p>
      </section></div>

      <section className="submission-card" aria-label="Assigned engines">
        <div className="client-section-heading"><div><p className="eyebrow">AUTOMATION ROUTING</p><h2>Engines this client would run</h2></div>
          <ClientPanelLink className="button button-secondary" clientId={clientId} tab="profiles">Manage routing<ArrowRight size={14} aria-hidden="true" /></ClientPanelLink></div>
        {!data.engines.length && <p>No engines are assigned to the default profile.</p>}
        {data.engines.length > 0 && <div className="history-table-wrap"><table className="history-table client-engine-table"><thead><tr>
          <th>Engine</th><th>Adapter</th><th>Eligible for API/ICAP</th><th>Reason</th></tr></thead><tbody>
          {data.engines.map(engine => <tr key={engine.id}><td>{engine.display_name}</td><td>{engine.adapter_key}</td>
            <td><span className={`client-badge ${engine.eligible ? 'client-badge-enabled' : ''}`}>{engine.eligible ? 'Eligible' : 'Excluded'}</span></td><td>{engine.excluded_reason || 'Available for automation routing.'}</td></tr>)}</tbody></table></div>}
        <p className="muted client-note">Eligibility is configuration, not health: an eligible engine can still be unavailable at scan time.
          Assigned engines are fixed into each accepted scan, so editing routing later does not change scans already accepted.</p>
      </section>

      <p className="muted client-note">Readiness read {new Date(data.generated_at).toLocaleString()}. Network reachability, TLS and firewall
        rules are outside MASP and are not checked here.</p>
    </>}
  </section>
}
