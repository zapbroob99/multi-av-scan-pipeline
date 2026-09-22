import { Fragment } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import { Button } from '../components/ui/button'

const DOES = [
  ['Orchestrates engines', 'Routes scans to configured ClamAV, Defender, YARA, metadata and reputation adapters.'],
  ['Normalizes evidence', 'Converts engine output into verdicts, severity, confidence, findings and analyst reports.'],
  ['Separates consumers', 'Service clients can own API credentials, ledger entries and engine routing.'],
  ['Keeps quota explicit', 'API and ICAP traffic do not spend external reputation quota engines such as VirusTotal.'],
]

const DOES_NOT = [
  ['Not an antivirus engine', 'It runs and coordinates engines; detection quality comes from the configured adapters.'],
  ['Not a secret vault replacement', 'It encrypts supported secrets when configured, but deployment secrets still belong in operations tooling.'],
  ['Not a sandbox detonator yet', 'Dynamic detonation and behavioral analysis remain future engine integrations.'],
  ['Not a generic command runner', 'Adapters stay typed and constrained so engine execution remains supportable.'],
]

export default function About({ session }: { session: Session }) {
  const about = useQuery({ queryKey: ['about'], queryFn: ({ signal }) => request('/api/ui/v1/about', 'get', { signal }),
    retry: false, gcTime: 60000, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })
  const data = about.data
  return <section className="page management-page"><div className="page-heading"><div><p className="eyebrow">PRODUCT</p>
    <h1>About MASP</h1><p className="muted">Self-hosted multi-engine malware scan orchestration for files, hashes, APIs and ICAP gateways.</p></div>
    <Button variant="secondary" disabled={about.isFetching} onClick={() => { void about.refetch() }}>Refresh snapshot</Button></div>
    <p>MASP coordinates antivirus and reputation engines, stores normalized evidence, scores scan results and keeps file content inside your own infrastructure.</p>
    <div className="about-columns">
      <section className="submission-card"><h2>What MASP does</h2><dl className="report-metadata">
        {DOES.map(([term, detail]) => <Fragment key={term}><dt>{term}</dt><dd>{detail}</dd></Fragment>)}</dl></section>
      <section className="submission-card"><h2>What MASP is not</h2><dl className="report-metadata">
        {DOES_NOT.map(([term, detail]) => <Fragment key={term}><dt>{term}</dt><dd>{detail}</dd></Fragment>)}</dl></section>
    </div>
    {about.isPending && <p role="status">Loading runtime snapshot…</p>}
    {about.error && <p role="alert" className="error">{about.error.message}</p>}
    {!about.error && data && <>
      <section className="submission-card"><h2>Runtime snapshot</h2>
        <p className="muted">Non-sensitive capability state from this MASP instance. Deployment hosts, paths and engine configuration are not shown.</p>
        <dl className="report-metadata">
          <dt>Application</dt><dd>MASP {data.app_version}</dd>
          <dt>Queue model</dt><dd>{data.queue_mode}</dd>
          <dt>Worker transport</dt><dd>{data.worker_transport}</dd>
          <dt>Directory login</dt><dd>{data.directory_login_enabled ? 'Enabled' : 'Disabled'}</dd>
          <dt>Secret encryption</dt><dd>{data.secret_encryption_available ? 'Available' : 'Not configured'}</dd>
          <dt>External quota engines</dt><dd>Excluded from API and ICAP</dd>
          <dt>Enabled engines</dt><dd>{data.enabled_engine_count}{data.enabled_engine_names.length
            ? `: ${data.enabled_engine_names.join(', ')}${data.engine_names_truncated ? ' and more' : ''}` : ''}</dd>
          <dt>Hash engines</dt><dd>{data.hash_engine_count}</dd>
          <dt>Worker nodes</dt><dd>{data.registered_nodes} registered · {data.schedulable_nodes} accepting work</dd>
          {data.service_client_count !== null && <><dt>Service clients</dt><dd>{data.service_client_count}</dd></>}
        </dl>
        <p className="muted">Enabled engines and schedulable nodes are configuration state, not proof that a scan will reach complete coverage.
          Snapshot read {new Date(data.generated_at).toLocaleString()}; it is not cached.</p>
      </section>
      <section className="submission-card"><h2>Primary interfaces</h2>
        <nav className="report-actions" aria-label="Primary interfaces">
          <Link to="/scans/new">Manual file scan</Link><Link to="/hash-scan">Hash scan</Link><Link to="/api-ledger">API ledger</Link>
          {session.user.role === 'admin' && <Link to="/service-clients">Service clients</Link>}
        </nav>
        <p className="muted">The ICAP gateway is a separate process for network and storage integrations; it has no console screen.</p>
      </section>
    </>}
  </section>
}
