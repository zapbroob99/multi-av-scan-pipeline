import { useEffect, useId, useRef, useState, type FormEvent } from 'react'
import { request, type Session } from '../lib/api'
import type { components } from '../lib/api.generated'
import { Button } from './ui/button'
import { ErrorMessage } from './error-message'
import { Timestamp } from './timestamp'
import { conditionText } from './profile-rules'
import { formatBytes } from '../lib/storage'

type Configuration = components['schemas']['ClientConfiguration']
type Preview = components['schemas']['RulePreview']
const ACTIONS = { scan: 'Scan', light: 'Light check', allow: 'Allow without scanning', block: 'Block' }
const LIMITS = { blocked: 'Unavailable', exceeds_limit: 'Exceeds limit', within_limit: 'Within size limit', unknown: 'Not established' }

export function RulePreview({ configuration, source, session }: { configuration: Configuration; source: 'api' | 'icap'; session: Session }) {
  const id = useId()
  const inflight = useRef<AbortController | null>(null)
  const [size, setSize] = useState('')
  const [unit, setUnit] = useState('mib')
  const [extension, setExtension] = useState('')
  const [header, setHeader] = useState('')
  const [result, setResult] = useState<Preview | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => () => { inflight.current?.abort() }, [])
  function clearResult() {
    inflight.current?.abort()
    setResult(null); setError(''); setBusy(false)
  }
  async function preview(event: FormEvent) {
    event.preventDefault()
    clearResult()
    const bytes = Number(size) * (unit === 'mib' ? 1024 * 1024 : 1)
    if (!size.trim() || !Number.isSafeInteger(bytes) || bytes < 0) {
      setError('Enter a size that resolves to a whole number of bytes, from 0 to 9,007,199,254,740,991.'); return
    }
    const ext = extension.trim().replace(/^\./, '').toLowerCase()
    if (!/^[a-z0-9]{0,16}$/.test(ext)) { setError('Use an extension of at most 16 letters or digits, or leave it blank.'); return }
    const profile = configuration.profile!
    const controller = new AbortController()
    inflight.current = controller
    setBusy(true)
    try {
      const response = await request('/api/ui/v1/service-clients/{client_id}/configuration/preview', 'post', {
        params: { client_id: configuration.client_id }, csrf: session.csrf_token, signal: controller.signal,
        body: { profile_id: profile.id, expected_revision: profile.management_revision, source,
          size_bytes: bytes, extension: ext, header_type: header || null },
      })
      if (!controller.signal.aborted) setResult(response)
    } catch (cause) {
      if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Preview unavailable.')
    } finally {
      if (!controller.signal.aborted) setBusy(false)
    }
  }
  return <details className="rule-preview"><summary>Try a file against saved rules</summary>
    <p className="muted">Enter hypothetical file metadata. No file is uploaded, no scan is created and no provider quota is used.</p>
    <form aria-label="Rule preview" onSubmit={preview}>
      <div className="configuration-selectors">
        <div><label htmlFor={`${id}-size`}>File size</label><input id={`${id}-size`} required type="number" min="0" step="any" value={size}
          onChange={event => { clearResult(); setSize(event.target.value) }} /></div>
        <div><label htmlFor={`${id}-unit`}>Size unit</label><select id={`${id}-unit`} value={unit} onChange={event => { clearResult(); setUnit(event.target.value) }}>
          <option value="mib">MiB</option><option value="bytes">Bytes</option></select></div>
        <div><label htmlFor={`${id}-extension`}>Declared extension</label><input id={`${id}-extension`} value={extension} maxLength={17} placeholder="e.g. pdf"
          aria-describedby={`${id}-header-help`} onChange={event => { clearResult(); setExtension(event.target.value) }} /></div>
        <div><label htmlFor={`${id}-header`}>Header content type</label><select id={`${id}-header`} value={header} aria-describedby={`${id}-header-help`}
          onChange={event => { clearResult(); setHeader(event.target.value) }}>
          <option value="">Unknown / not inspected</option><option value="unrecognized">Inspected, no recognized signature</option>
          {configuration.header_types.map(type => <option key={type.key} value={type.key}>{type.key.toUpperCase().replaceAll('_', ' ')} ({type.family})</option>)}
        </select></div>
      </div>
      <p id={`${id}-header-help`} className="muted">Header type must come from content inspection. An extension does not establish the file's content; it can add a script or executable family under existing rules.</p>
      <Button type="submit" variant="secondary" disabled={busy}>{busy ? 'Checking rules…' : 'Preview saved rules'}</Button>
    </form>
    {error && <p role="alert" className="error"><ErrorMessage message={error} /></p>}
    {result && <section className="rule-preview-result" aria-label="Rule preview result">
      <h3>{result.status === 'matched' ? `Matches rule ${result.matches[0].number}` : 'Matching rule cannot be determined'}</h3>
      <p className="muted">Saved profile revision {result.profile_revision} · <Timestamp value={new Date(result.observed_at * 1000).toISOString()} />.
        {' '}Rules below describe hypothetical routing even when a transport limit prevents scanning.</p>
      {result.matches.map(match => <div className="configuration-engine" key={match.number}>
        <p><strong>Rule {match.number}: {ACTIONS[match.action]}</strong></p>
        <p>{conditionText(configuration.profile!.rules!.rules[match.number - 1], match.number === configuration.profile!.rules!.rules.length)}</p>
        <p>Selected engines: {match.engine_ids.length ? match.engine_ids.map(engineId => result.engines.find(engine => engine.id === engineId)?.name ?? `Engine #${engineId}`).join(', ') : 'None'}.</p>
        {match.archive && <p>For archives: {{ whole: 'scan as one file', inspect: 'open and check', members: 'scan every member' }[match.archive]}.</p>}
      </div>)}
      <dl className="preview-limits">{result.limits.map((limit, index) => <div key={index}><dt>{limit.label}</dt>
        <dd><strong>{LIMITS[limit.state]}</strong>{limit.limit_bytes != null && <> · {limit.limit_bytes === 0 ? 'No limit at this layer' : formatBytes(limit.limit_bytes)}</>}
          <p className="muted">{limit.explanation}</p></dd></div>)}</dl>
      <details open={result.status === 'ambiguous'}><summary>Preview scope and limitations</summary>
        <ul>{result.warnings.map((warning, index) => <li key={index}>{warning}</li>)}</ul>
        <p className="muted">Configuration reference: <code className="configuration-reference">{result.configuration_fingerprint}</code></p>
      </details>
    </section>}
  </details>
}
