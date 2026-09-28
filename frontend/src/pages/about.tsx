import type { ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { RefreshCw } from 'lucide-react'
import { request, type Session } from '../lib/api'
import { Button } from '../components/ui/button'

function Spec({ title, children }: { title: string; children: ReactNode }) {
  return <section className="spec-panel"><h2>{title}</h2><dl className="spec-list">{children}</dl></section>
}

function Row({ term, children, mono = false }: { term: string; children: ReactNode; mono?: boolean }) {
  return <div className="spec-row"><dt>{term}</dt><dd className={mono ? 'mono' : undefined}>{children}</dd></div>
}

const orDash = (value: string | null | undefined) => value || '—'
const when = (iso: string | null) => iso ? new Date(iso).toLocaleString() : '—'

export default function About({ session }: { session: Session }) {
  const about = useQuery({ queryKey: ['about'], queryFn: ({ signal }) => request('/api/ui/v1/about', 'get', { signal }),
    retry: false, gcTime: 60000, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })
  const data = about.data
  return <section className="page management-page about-page"><div className="page-heading"><div><p className="eyebrow">SYSTEM</p>
    <h1>About MASP</h1><p className="muted">Multi-engine malware scan orchestration. Build, component and engine versions of this instance.</p></div>
    <Button variant="secondary" disabled={about.isFetching} onClick={() => { void about.refetch() }}><RefreshCw size={14} aria-hidden="true" />Refresh</Button></div>

    {about.isPending && <p role="status">Loading runtime snapshot…</p>}
    {about.error && <p role="alert" className="error">{about.error.message}</p>}
    {!about.error && data && <>
      <Spec title="Build">
        <Row term="Application" mono>MASP {data.app_version}</Row>
        <Row term="Release image" mono>{orDash(data.release)}</Row>
        <Row term="Python" mono>{data.python_version}</Row>
        <Row term="Database" mono>{data.database}</Row>
        <Row term="Queue model">{data.queue_mode}</Row>
        <Row term="Worker transport">{data.worker_transport}</Row>
      </Spec>

      <section className="spec-panel"><h2>Engines</h2>
        {data.engines.length ? <div className="history-table-wrap spec-table-wrap"><table className="history-table spec-table">
          <thead><tr><th>Engine</th><th>Adapter</th><th>Product</th><th>Engine version</th><th>Signatures</th><th>Last check</th></tr></thead>
          <tbody>{data.engines.map(engine => <tr key={engine.name + engine.kind}>
            <td>{engine.name}</td><td>{engine.kind}</td><td className="mono">{orDash(engine.product_version)}</td>
            <td className="mono">{orDash(engine.engine_version)}</td><td className="mono">{orDash(engine.signature_version)}</td>
            <td>{when(engine.last_checked_at)}</td></tr>)}</tbody>
        </table></div> : <p className="muted spec-empty">No engine is enabled.</p>}
        <p className="spec-note">{data.enabled_engine_count} enabled{data.engines_truncated ? `; the first ${data.engines.length} are listed` : ''}.
          Versions are the latest a worker reported in its engine health check; — means no check has reported one yet.</p>
      </section>

      <Spec title="Workers">
        <Row term="Worker nodes">{data.registered_nodes} registered · {data.schedulable_nodes} accepting work</Row>
        <Row term="Agent versions" mono>{data.worker_agent_versions.length ? data.worker_agent_versions.join(', ') : '—'}</Row>
      </Spec>

      <Spec title="Configuration">
        <Row term="Directory login">{data.directory_login_enabled ? 'Enabled' : 'Disabled'}</Row>
        <Row term="Secret encryption">{data.secret_encryption_available ? 'Available' : 'Not configured'}</Row>
        <Row term="Hash engines">{data.hash_engine_count}</Row>
        <Row term="External quota engines">Excluded from API and ICAP</Row>
        {session.user.role === 'admin' && data.service_client_count !== null && <Row term="Service clients">{data.service_client_count}</Row>}
      </Spec>

      <p className="spec-note">Snapshot read {new Date(data.generated_at).toLocaleString()}; it is not cached. Hosts, paths and engine
        configuration are never shown here. Enabled engines and accepting nodes are configuration state, not proof that a scan will reach complete coverage.</p>
    </>}
  </section>
}
