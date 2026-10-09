import { ErrorMessage } from '../components/error-message'
import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { request, type FileHistory as History, type Session } from '../lib/api'
import { Button } from '../components/ui/button'
import { ExceptionBadge, NotAllowedBadge, RiskBadge, RuleBadge } from '../components/risk-badge'
import { Timestamp } from '../components/timestamp'

const SHA256 = /^[0-9a-fA-F]{64}$/
const ACTIVE = new Set(['queued', 'running', 'finalizing'])

/** Where a scan's report lives; scans from other sources have no report screen. */
export function reportPath(scan: { id: number; source: string }): string | null {
  if (scan.source === 'manual') return `/scans/${scan.id}`
  if (scan.source === 'api' || scan.source === 'icap') return `/api-ledger/scans/${scan.id}`
  return null
}

function engineResult(engine: NonNullable<History['last_engines']>[number]) {
  if (engine.detected) return <><strong>Detected</strong>{engine.signature ? <> · <code>{engine.signature}</code></> : null}</>
  if (engine.status === 'completed') return 'No detection'
  return <span className="health-pill health-failed">{engine.status}</span>
}

/** MASP's own record of one file, by SHA-256. Never a verdict: a later signature
 * update can change what the engines would say, and external reputation is a
 * separate lookup that this page does not run. */
export default function FileHistory({ session }: { session: Session }) {
  const { sha256 = '' } = useParams()
  const valid = SHA256.test(sha256)
  const digest = sha256.toLowerCase()
  const history = useQuery({ queryKey: ['file-history', digest], enabled: valid, retry: false, gcTime: 60000,
    queryFn: ({ signal }) => request('/api/ui/v1/files/{sha256}', 'get', { params: { sha256: digest }, signal }) })
  const admin = session.user.role === 'admin'
  const file = history.error ? undefined : history.data
  const engines = file?.last_engines ?? []

  if (!valid) return <section className="page"><h1>Invalid SHA-256</h1>
    <p className="muted">A file is named by its full SHA-256: 64 hexadecimal characters.</p><Link to="/hash-scan">Hash lookup</Link></section>

  return <section className="page file-history-page"><div className="page-heading"><div><p className="eyebrow">FILE</p><h1>File history</h1>
    <p className="muted"><code className="hash-value">{digest}</code></p></div>
    <div className="report-actions"><Link className="button button-secondary" to={`/hash-scan?sha256=${digest}`}>Ask external engines</Link>
      <Button variant="secondary" disabled={history.isFetching} onClick={() => { void history.refetch() }}>Refresh</Button></div></div>
    <p className="callout">What this MASP deployment's own engines recorded about this exact file, at the times shown. It is not a current
      verdict: signatures change after a scan. External reputation is a separate lookup that this page does not run.</p>

    {history.isPending && <p className="skeleton" role="status">Loading file history…</p>}
    {history.error && <p role="alert" className="error"><ErrorMessage message={history.error.message || ''} /></p>}
    {file && <>
      {!file.seen ? <section className="empty"><h2>MASP has not scanned this file</h2>
        <p>No scan of this SHA-256 has finished here. That says nothing about whether the file is safe.</p></section> : <>
        <div className="stats-row dashboard-stats" aria-label="Recorded file history">
          <div><span>Scans</span><strong>{(file.scan_count ?? 0).toLocaleString()}</strong></div>
          <div><span>With a detection</span><strong>{(file.detected_count ?? 0).toLocaleString()}</strong></div>
          <div><span>First seen</span><strong className="stat-time"><Timestamp value={file.first_seen_at} /></strong></div>
          <div><span>Last seen</span><strong className="stat-time"><Timestamp value={file.last_seen_at} /></strong></div>
        </div>
        {file.last_detected_at != null && <p className="muted">Last detection recorded <Timestamp value={file.last_detected_at} />.</p>}

        <section className="file-history-latest" aria-labelledby="file-latest-heading">
          <h2 id="file-latest-heading">Latest scan</h2>
          <p className="report-not-allowed">
            <RiskBadge level={file.last_verdict || ''} score={file.last_risk_score ?? null}
              pending={ACTIVE.has(file.last_status || '')} failed={file.last_status === 'failed'} />
            {file.last_not_allowed_label && <NotAllowedBadge label={file.last_not_allowed_label} />}
            <RuleBadge action={file.last_rule_action} />
          </p>
          {engines.length === 0 ? <p className="muted">No engine result was recorded for the latest scan.</p> :
            <div className="history-table-wrap" tabIndex={0} role="region" aria-label="Latest engine results"><table className="history-table">
              <thead><tr><th scope="col">Engine</th><th scope="col">Result</th><th scope="col">Engine version</th><th scope="col">Signatures</th></tr></thead>
              <tbody>{engines.map((engine, index) => <tr key={`${engine.engine_name}-${index}`}>
                <td>{engine.engine_name}</td><td>{engineResult(engine)}</td>
                <td>{engine.engine_version || 'Not recorded'}</td><td>{engine.signature_version || 'Not recorded'}</td></tr>)}</tbody>
            </table></div>}
        </section>
      </>}

      <section aria-labelledby="file-lists-heading">
        <h2 id="file-lists-heading">Hash list and exceptions</h2>
        <dl className="submission-card report-metadata">
          <dt>Hash list</dt><dd>{file.hash_list === 'block' ? 'Blocklist' : file.hash_list === 'allow' ? 'Allowlist (informational)' : 'Not listed'}
            {admin && <> · <Link to={`/engines/hash-list?q=${digest}`}>Hash list</Link></>}</dd>
          <dt>Exceptions</dt><dd>{file.exceptions.length === 0 ? 'None active' :
            <ul className="plain-list">{file.exceptions.map(item => <li key={item.id}>#{item.id} · {item.scope} · {item.reason}</li>)}</ul>}
            {admin && <> <Link to={`/engines/exceptions?state=all&q=${digest}`}>Exceptions</Link></>}</dd>
        </dl>
      </section>

      <section aria-labelledby="file-scans-heading">
        <h2 id="file-scans-heading">Recent scans</h2>
        {file.recent_scans.length === 0 ? <p className="muted">{file.seen
          ? 'The scans themselves are no longer kept (retention or deletion); the history above remains.' : 'None.'}</p> :
          <><div className="history-table-wrap" tabIndex={0} role="region" aria-label="Recent scans of this file"><table className="history-table">
            <thead><tr><th scope="col">File name</th><th scope="col">Source</th><th scope="col">Status</th><th scope="col">Recorded risk</th><th scope="col">Submitted</th></tr></thead>
            <tbody>{file.recent_scans.map(scan => {
              const path = reportPath(scan)
              return <tr key={scan.id}>
                <td>{path ? <Link className="sample-link" to={path}>{scan.filename}</Link> : scan.filename}
                  <small>Scan #{scan.id}{scan.scan_role === 'child' ? ' · Archive member' : ''}</small></td>
                <td>{scan.source}{scan.client_name ? ` · ${scan.client_name}` : ''}</td>
                <td><span className={`health-pill ${['failed', 'skipped'].includes(scan.status) ? 'health-failed' : ''}`}>{scan.status}</span></td>
                <td><RiskBadge level={scan.verdict} score={scan.risk_score} pending={ACTIVE.has(scan.status)} failed={scan.status === 'failed'} />
                  {scan.not_allowed_label && <NotAllowedBadge label={scan.not_allowed_label} />}<RuleBadge action={scan.rule_action} />
                  <ExceptionBadge id={scan.exception_id} /></td>
                <td><Timestamp value={scan.created_at} /></td></tr>
            })}</tbody></table></div>
            <p className="muted">Newest {file.recent_scans.length} shown. The counts above also include scans no longer kept.</p></>}
      </section>
    </>}
  </section>
}
