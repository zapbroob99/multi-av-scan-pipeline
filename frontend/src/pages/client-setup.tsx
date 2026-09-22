import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { request } from '../lib/api'
import { Button } from '../components/ui/button'

export default function ClientSetup() {
  const { clientId = '' } = useParams()
  const valid = /^\d+$/.test(clientId) && Number.isSafeInteger(Number(clientId)) && Number(clientId) > 0
  const setup = useQuery({ queryKey: ['client-readiness', clientId], enabled: valid,
    queryFn: ({ signal }) => request('/api/ui/v1/service-clients/{client_id}/readiness', 'get', {
      params: { client_id: Number(clientId) }, signal }),
    staleTime: 0, gcTime: 0, retry: false, refetchOnMount: 'always',
    refetchOnWindowFocus: false, refetchOnReconnect: false, refetchInterval: false })
  if (!valid) return <section className="page"><h1>Invalid client ID</h1><Link to="/service-clients">Service clients</Link></section>
  const data = !setup.error && !setup.isFetching ? setup.data : undefined
  const blocking = data?.checks.filter(check => !check.passed) ?? []
  return <section className="page management-page"><div className="page-heading"><div><p className="eyebrow">INTEGRATIONS</p>
    <h1>Connect a client</h1><p className="muted">Configuration readiness and the values the other system needs.</p></div>
    <Button variant="secondary" disabled={setup.isFetching} onClick={() => { void setup.refetch() }}>Refresh readiness</Button></div>
    <p><Link to="/service-clients">All service clients</Link> · <Link to={`/service-clients/${clientId}/profiles`}>Profile routing</Link>
      {' · '}<Link to={`/service-clients/${clientId}/credentials`}>Credentials</Link></p>
    {setup.isFetching && <p role="status">Loading client readiness…</p>}
    {setup.error && <p role="alert" className="error">{setup.error.message}</p>}
    {data && <>
      <section className="submission-card" aria-label="Readiness">
        <h2>{data.display_name} <span className="muted">({data.client_key})</span></h2>
        <p className={data.ready ? 'callout' : 'error'} role={data.ready ? undefined : 'alert'}>
          {data.ready
            ? 'Configuration is complete. This does not prove the integration can reach MASP or that its token is correct.'
            : `Not ready: ${blocking.length} item(s) still need attention.`}</p>
        <ul className="readiness-list">{data.checks.map(check => <li key={check.key} className={check.passed ? 'readiness-pass' : 'readiness-fail'}>
          <strong>{check.passed ? 'Ready' : 'Action needed'} — {check.label}</strong><span>{check.detail}</span></li>)}</ul>
        {data.managed && <p className="callout">Managed compatibility client. Its routing follows deployment configuration rather than this profile.</p>}
      </section>

      <section className="submission-card" aria-label="Connection details">
        <h2>Point the other system here</h2>
        <dl className="report-metadata">
          <dt>Submit a file</dt><dd>POST {data.scan_endpoint}</dd>
          <dt>Poll a scan</dt><dd>GET {data.status_endpoint}</dd>
          <dt>Large-file intake</dt><dd>POST {data.deferred_endpoint}</dd>
          <dt>Authentication</dt><dd>{data.authorization_header}</dd>
          <dt>ICAP gateway</dt><dd>{data.icap_client_key_setting}</dd>
        </dl>
        <p className="muted">A credential value is never shown after it is saved; MASP stores only its hash. Issue a new
          credential if the integration no longer has its token. An ICAP gateway carries no bearer token: bind a dedicated
          listener to this client key instead, and keep the host firewall authoritative for source control.</p>
      </section>

      <section className="submission-card" aria-label="Assigned engines">
        <h2>Engines this client would run</h2>
        {!data.engines.length && <p>No engines are assigned to the default profile.</p>}
        {data.engines.length > 0 && <div className="history-table-wrap"><table className="history-table"><thead><tr>
          <th>Engine</th><th>Adapter</th><th>Eligible for API/ICAP</th><th>Reason</th></tr></thead><tbody>
          {data.engines.map(engine => <tr key={engine.id}><td>{engine.display_name}</td><td>{engine.adapter_key}</td>
            <td>{engine.eligible ? 'Yes' : 'No'}</td><td>{engine.excluded_reason || '-'}</td></tr>)}</tbody></table></div>}
        <p className="muted">Eligibility is configuration, not health: an eligible engine can still be unavailable at scan time.
          Assigned engines are fixed into each accepted scan, so editing routing later does not change scans already accepted.</p>
      </section>

      <p className="muted">Readiness read {new Date(data.generated_at).toLocaleString()}. Network reachability, TLS and firewall
        rules are outside MASP and are not checked here.</p>
    </>}
  </section>
}
