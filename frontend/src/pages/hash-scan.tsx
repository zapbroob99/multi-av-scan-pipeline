import { ErrorMessage } from '../components/error-message'
import { useState, type FormEvent } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { ExternalLink, History, RefreshCw, Search, ShieldAlert, ShieldCheck, ShieldX } from 'lucide-react'
import { request, type FileHistory, type Session } from '../lib/api'
import { Button } from '../components/ui/button'
import { NotAllowedBadge, RiskBadge, RuleBadge } from '../components/risk-badge'
import { Timestamp } from '../components/timestamp'

/** What the operator should do with the file, matching the legacy page. */
export const GUIDANCE: Record<'allow' | 'review' | 'block', string> = {
  block: 'Threat signal detected. Do not release this file; reject or quarantine it according to your gateway policy.',
  review: 'Manual review required. Keep the file quarantined until an analyst or a full content scan resolves the uncertainty.',
  allow: 'Reputation policy passed: every enabled hash engine returned an allow decision under its configured policy.',
}

const VERDICT_ICON = { allow: ShieldCheck, review: ShieldAlert, block: ShieldX }
const HEX = /^[0-9a-fA-F]*$/
const SHA256 = /^[0-9a-fA-F]{64}$/

/** What MASP's own engines recorded about the file. Free and local: it asks no provider,
 * and it is never folded into the reputation decision below. */
function SeenInMasp({ sha256, history, error }: { sha256: string; history?: FileHistory; error?: string }) {
  return <section className="hash-local" aria-label="Seen in MASP">
    <div className="hash-local-head"><History size={16} aria-hidden="true" /><h2>Seen in MASP</h2>
      {history?.seen && <Link to={`/files/${sha256}`}>Open file history</Link>}</div>
    {error ? <p role="alert" className="error"><ErrorMessage message={error} /></p>
      : !history ? <p role="status" className="muted">Reading MASP's own records…</p>
      : !history.seen ? <p>MASP has not scanned this file. That says nothing about whether it is safe.</p> : <>
        <p className="hash-local-badges"><RiskBadge level={history.last_verdict || ''} score={history.last_risk_score ?? null}
          failed={history.last_status === 'failed'} />
          {history.last_not_allowed_label && <NotAllowedBadge label={history.last_not_allowed_label} />}
          <RuleBadge action={history.last_rule_action} /></p>
        <p>Scanned {(history.scan_count ?? 0).toLocaleString()} time{history.scan_count === 1 ? '' : 's'} ·
          {' '}{(history.detected_count ?? 0).toLocaleString()} with a detection · Last seen <Timestamp value={history.last_seen_at} />
          {history.last_detected_at != null && <> · Last detection <Timestamp value={history.last_detected_at} /></>}</p>
        {(history.last_engines ?? []).filter(engine => engine.detected).map((engine, index) =>
          <p key={index} className="muted">{engine.engine_name}: <code>{engine.signature || 'detected'}</code>
            {engine.signature_version ? ` · Signatures ${engine.signature_version}` : ''}</p>)}
        {history.hash_list === 'block' && <p className="muted">On the hash blocklist.</p>}
        {history.exceptions.length > 0 && <p className="muted">An active exception allows this file ({history.exceptions.length}).</p>}
      </>}
    <p className="muted hash-result-footnote">Recorded by this deployment's engines at the times shown; not a current verdict.</p>
  </section>
}

type Stats = { malicious: number; suspicious: number; undetected: number; harmless: number; total: number }

/** Proportional bar of provider verdicts; the text beside it carries the exact numbers. */
function VerdictBar({ stats }: { stats: Stats }) {
  const total = Math.max(stats.total, 1)
  const parts: [keyof Stats, number][] = [['malicious', stats.malicious], ['suspicious', stats.suspicious],
    ['harmless', stats.harmless], ['undetected', stats.undetected]]
  return <div className="verdict-bar" aria-hidden="true">
    {parts.filter(([, count]) => count > 0).map(([kind, count]) =>
      <span key={kind} className={`verdict-bar-${kind}`} style={{ width: `${(count / total) * 100}%` }} />)}
  </div>
}

export default function HashScan({ session }: { session: Session }) {
  const [params] = useSearchParams()
  const [sha256, setSha256] = useState(() => (params.get('sha256') || '').trim().slice(0, 64))
  const options = useQuery({ queryKey: ['hash-options'], queryFn: ({ signal }) => request('/api/ui/v1/hash-scan/options', 'get', { signal }),
    retry: false, gcTime: 0, refetchOnWindowFocus: false, refetchOnReconnect: false })
  const lookup = useMutation({ retry: false, gcTime: 0, mutationFn: (hash: string) => request('/api/ui/v1/hash-scan', 'post', {
    csrf: session.csrf_token, body: { sha256: hash } }) })
  const value = sha256.trim()
  const digest = SHA256.test(value) ? value.toLowerCase() : ''
  // The local record is read as soon as a full digest is entered: it costs nothing and asks no provider.
  const local = useQuery({ queryKey: ['file-history', digest], enabled: Boolean(digest), retry: false, gcTime: 60000,
    queryFn: ({ signal }) => request('/api/ui/v1/files/{sha256}', 'get', { params: { sha256: digest }, signal }) })
  // Enter never spends provider quota; only the explicit button below does.
  function submit(event: FormEvent) { event.preventDefault() }
  function askExternal() { if (!lookup.isPending && digest) lookup.mutate(digest) }

  const length = value.length
  const invalidChars = !HEX.test(value)
  const engines = options.data?.engines ?? []
  const hint = invalidChars ? 'Only hexadecimal characters (0-9, a-f) are allowed.'
    : length === 64 ? 'Valid SHA-256 length.' : `${length} / 64 hexadecimal characters`
  const result = lookup.data && !lookup.error && !lookup.isPending ? lookup.data : null
  const Icon = result ? VERDICT_ICON[result.action] : null

  return <section className="page management-page hash-page"><div className="page-heading"><div><p className="eyebrow">MANUAL LOOKUP</p><h1>Hash lookup</h1>
    <p className="muted">See what MASP already recorded about a file, then ask external reputation providers only if you need to. No file content is uploaded.</p></div></div>

    <form className="hash-lookup-panel" onSubmit={submit}>
      <label htmlFor="lookup-sha256" className="hash-lookup-label">SHA-256</label>
      <div className="hash-lookup-row">
        <div className="hash-lookup-field">
          <Search size={16} aria-hidden="true" />
          <input id="lookup-sha256" required minLength={64} maxLength={64} pattern="[0-9a-fA-F]{64}" autoComplete="off" spellCheck={false}
            placeholder="e.g. 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" aria-describedby="lookup-sha256-hint"
            value={sha256} disabled={lookup.isPending} onChange={event => { setSha256(event.target.value); lookup.reset() }} />
        </div>
        <Button type="button" onClick={askExternal} disabled={!digest || lookup.isPending || options.isFetching || !!options.error || !engines.length}>
          {lookup.isPending ? 'Asking…' : 'Ask external engines (uses quota)'}</Button>
      </div>
      <p id="lookup-sha256-hint" className={`hash-lookup-hint${invalidChars ? ' is-invalid' : length === 64 ? ' is-valid' : ''}`}>{hint}</p>

      <div className="hash-lookup-providers">
        <span className="hash-lookup-providers-label">Providers</span>
        {options.isPending && <span role="status" className="muted">Loading hash engines…</span>}
        {options.data && (engines.length
          ? <span className="sr-only">Enabled hash engines: {engines.map(e => e.name).join(', ')}</span>
          : <span className="muted">No hash-capable engine is added and enabled in MASP.</span>)}
        {engines.map(engine => <span key={engine.id} className="tag tag-accent">{engine.name}</span>)}
        <Button type="button" variant="secondary" className="hash-lookup-refresh" disabled={options.isFetching || lookup.isPending}
          onClick={() => { void options.refetch() }}><RefreshCw size={14} aria-hidden="true" />Refresh engines</Button>
      </div>
      {options.error && <p role="alert" className="error"><ErrorMessage message={options.error.message || ''} /></p>}
      <p className="hash-lookup-note">Asking external engines sends the hash to enabled reputation providers and may consume external quota. Reputation is not a file scan or proof of complete detection coverage.
        No automatic retry, polling or scan-history record is created, and the answer is not added to MASP's own records.</p>
    </form>

    {digest && <SeenInMasp sha256={digest} history={local.error ? undefined : local.data}
      error={local.error ? local.error.message || 'MASP history could not be read.' : undefined} />}

    {lookup.error && <p role="alert" className="error"><ErrorMessage message={lookup.error.message || ''} /> The request may have reached a provider and consumed quota. No complete decision is available. Retry only as an explicit new lookup.</p>}

    {result && Icon && <section className="hash-result" aria-label="Hash lookup result">
      <div className={`hash-verdict verdict-${result.action}`}>
        <Icon size={28} aria-hidden="true" />
        <div>
          <h2>Reputation decision: {result.action}</h2>
          <p>{result.reason}</p>
          <p className="hash-verdict-guidance">{GUIDANCE[result.action]}</p>
        </div>
      </div>
      <p className="hash-result-digest"><span>SHA-256</span><code className="hash-value">{result.sha256}</code></p>

      <ul className="hash-providers">
        {result.results.map(row => <li key={row.id} className="hash-provider">
          <div className="hash-provider-head">
            <h3>{row.name}</h3>
            <span className={`tag tag-dot ${row.action === 'allow' ? 'tag-positive' : row.action === 'block' ? 'tag-danger' : 'tag-warning'}`}>{row.action}</span>
          </div>
          <p className="hash-provider-status">Decision: {row.action} · {row.found ? 'Hash found' : 'Hash not found'} · Provider status: {row.status}</p>
          {row.stats && <div className="hash-provider-stats"><VerdictBar stats={row.stats} />
            <p>{row.stats.malicious} malicious · {row.stats.suspicious} suspicious · {row.stats.undetected} undetected · {row.stats.harmless} harmless (of {row.stats.total})</p></div>}
          <dl className="hash-provider-facts">
            <div><dt>Last analysis</dt><dd>{row.last_analysis_date || 'Not reported'}</dd></div>
            <div><dt>Source</dt><dd>{row.cached === null ? 'Not reported' : row.cached ? 'MASP cache' : 'Live provider request'} · {row.duration_ms} ms</dd></div>
            {row.permalink && <div><dt>Report</dt><dd><a href={row.permalink} target="_blank" rel="noopener noreferrer">Open provider report<ExternalLink size={12} aria-hidden="true" /></a></dd></div>}
          </dl>
        </li>)}
      </ul>
      <p className="muted hash-result-footnote">This decision applies only to this reputation lookup. A missing hash does not establish that the file is clean.</p>
    </section>}
  </section>
}
