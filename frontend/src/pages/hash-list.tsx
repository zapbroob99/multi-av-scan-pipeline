import { useState, type FormEvent } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import type { components } from '../lib/api.generated'
import { Button } from '../components/ui/button'
import { Dialog } from '../components/ui/dialog'
import { SectionTabs, SYSTEM_TABS } from '../components/section-tabs'

type Entry = components['schemas']['HashListEntry']
type Added = components['schemas']['HashesAdded']
type Kind = 'block' | 'allow'

const MAX_ADD = 1000
const LABELS: Record<Kind, string> = { block: 'Blocklist', allow: 'Allowlist' }
const SHA256 = /^[0-9a-f]{64}$/

/** Hashes pasted one per line, or separated by spaces or commas. Only the
 * shape is checked here; the server validates every entry again before any
 * write, and rejects the whole request if one is malformed. */
export function parseHashes(text: string) {
  const values = text.split(/[\s,;]+/).map(value => value.trim().toLowerCase()).filter(Boolean)
  const invalid = values.filter(value => !SHA256.test(value))
  return { hashes: [...new Set(values.filter(value => SHA256.test(value)))], invalid }
}

export default function HashList({ session }: { session: Session }) {
  const client = useQueryClient()
  const [params, setParams] = useSearchParams()
  const query = new URLSearchParams(params)
  query.set('limit', '20')
  const entries = useQuery({ queryKey: ['hash-list', query.toString()],
    queryFn: ({ signal }) => request('/api/ui/v1/hash-list', 'get', { query, signal }),
    retry: false, staleTime: 0, gcTime: 0, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })
  const engines = useQuery({ queryKey: ['engines'], queryFn: ({ signal }) => request('/api/ui/v1/engines', 'get', { signal }),
    retry: false, refetchOnWindowFocus: false })
  const engineReady = engines.data?.engines.some(engine => engine.adapter_key === 'hash_list' && engine.enabled)

  const [kind, setKind] = useState<Kind | ''>('')
  const [text, setText] = useState('')
  const [note, setNote] = useState('')
  const [review, setReview] = useState<{ kind: Kind; hashes: string[] } | null>(null)
  const [removal, setRemoval] = useState<Entry | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [outcome, setOutcome] = useState<Added | null>(null)
  const [removed, setRemoved] = useState('')
  const parsed = parseHashes(text)

  function refresh() { void client.invalidateQueries({ queryKey: ['hash-list'] }) }
  function prepare(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError(''); setOutcome(null); setRemoved('')
    if (!kind) { setError('Choose a list explicitly.'); return }
    if (parsed.invalid.length) { setError(`Not a SHA-256 value: ${parsed.invalid[0].slice(0, 80)}`); return }
    if (!parsed.hashes.length) { setError('Paste at least one SHA-256 value.'); return }
    if (parsed.hashes.length > MAX_ADD) { setError(`Add at most ${MAX_ADD} hashes per request.`); return }
    setReview({ kind, hashes: parsed.hashes })
  }
  async function add() {
    if (!review) return
    setBusy(true); setError('')
    try {
      // No automatic retry: an uncertain outcome is resolved by reading the list again.
      setOutcome(await request('/api/ui/v1/hash-list', 'post', { csrf: session.csrf_token,
        body: { list_kind: review.kind, hashes: review.hashes, note: note.trim() } }))
      setText(''); setNote(''); setKind('')
    } catch (e) { setError(`${(e as Error).message} Refresh the list to see what was stored.`) }
    finally { setBusy(false); setReview(null); refresh() }
  }
  async function remove() {
    if (!removal) return
    setBusy(true); setError(''); setOutcome(null)
    try {
      await request('/api/ui/v1/hash-list/{entry_id}', 'delete', { params: { entry_id: removal.id }, csrf: session.csrf_token })
      setRemoved(`Removed ${removal.sha256} from the ${LABELS[removal.list_kind].toLowerCase()}.`)
    } catch (e) { setError((e as Error).message) }
    finally { setBusy(false); setRemoval(null); refresh() }
  }
  function filter(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget), next = new URLSearchParams()
    for (const key of ['q', 'kind']) {
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
  const counts = entries.data?.counts

  return <section className="page management-page">
    <SectionTabs tabs={SYSTEM_TABS} label="System sections" />
    <div className="page-heading"><div><p className="eyebrow">ENGINES</p><h1>Hash list</h1>
      <p className="muted">One institution-wide SHA-256 blocklist and allowlist, checked by the Hash List engine.</p></div>
      <Button variant="secondary" disabled={entries.isFetching} onClick={refresh}>Refresh list</Button></div>
    <p className="callout">A blocklist match is a detection and raises the recorded risk. An allowlist match is informational only:
      it never suppresses another engine's detection and never produces an allow decision. A hash that is not listed proves nothing about the file.
      Changes apply to engine jobs that run afterwards; completed results are not re-evaluated. MASP compares the digest it computed itself, never one a client supplied.</p>
    {engines.data && !engineReady && <p className="notice error" role="alert">No enabled Hash List engine exists. Entries are stored, but no scan checks them
      until an administrator adds the Hash List engine and assigns it to the relevant scan profiles.</p>}
    {counts && <p className="muted">{counts.block.toLocaleString()} blocked · {counts.allow.toLocaleString()} allowed</p>}

    <form onSubmit={prepare} className="submission-card" aria-label="Add hashes">
      <h2>Add hashes</h2>
      <label>Target list<select value={kind} required onChange={e => setKind(e.target.value as Kind | '')}>
        <option value="">Select a list</option><option value="block">Blocklist (detection)</option><option value="allow">Allowlist (informational)</option>
      </select></label>
      <label>SHA-256 values (one per line, up to {MAX_ADD})<textarea value={text} rows={6} spellCheck={false} onChange={e => setText(e.target.value)} /></label>
      <label>Note (optional, applies to every hash in this request)<input value={note} maxLength={256} onChange={e => setNote(e.target.value)} /></label>
      <p className="muted">{parsed.hashes.length} unique value{parsed.hashes.length === 1 ? '' : 's'}{parsed.invalid.length ? ` · ${parsed.invalid.length} invalid` : ''}.
        A hash already on either list is left unchanged and reported; move one by removing it first.</p>
      <Button type="submit" disabled={busy}>Review addition</Button>
    </form>

    {error && <p role="alert" className="error hash-value">{error}</p>}
    {removed && <p className="notice hash-value" role="status">{removed}</p>}
    {outcome && <div className="notice" role="status"><p>Added {outcome.added} hash{outcome.added === 1 ? '' : 'es'}.</p>
      {outcome.existing.length > 0 && <><p>{outcome.existing.length} already listed and left unchanged:</p>
        <ul>{outcome.existing.map(row => <li key={row.sha256}><code className="hash-value">{row.sha256}</code> — {row.list_kind === 'removed' ? 'removed concurrently' : `on the ${LABELS[row.list_kind].toLowerCase()}`}</li>)}</ul></>}</div>}

    <form key={params.toString()} onSubmit={filter} className="submission-card" aria-label="Hash list filters"><fieldset className="history-filters">
      <label>SHA-256 or note<input name="q" maxLength={200} defaultValue={params.get('q') || ''} /></label>
      <label>List<select name="kind" defaultValue={params.get('kind') || 'all'}>
        <option value="all">all</option><option value="block">blocklist</option><option value="allow">allowlist</option></select></label>
      <Button type="submit" disabled={entries.isFetching}>Apply filters</Button>
      <Button type="button" variant="secondary" onClick={() => setParams({})}>Reset filters</Button>
    </fieldset><p className="muted">A full SHA-256 matches exactly; shorter text matches a hash prefix or appears in the note. <code>%</code> and <code>_</code> are literal.</p></form>

    {entries.isPending && <p role="status">Loading hash list…</p>}
    {entries.error && <p role="alert" className="error">{entries.error.message}</p>}
    {!entries.error && entries.data && <>
      {!entries.data.items.length && <p className="empty">No hash list entries match these filters.</p>}
      {entries.data.items.length > 0 && <div className="history-table-wrap" role="region" aria-label="Hash list entries" tabIndex={0}>
        <table className="history-table compact-table"><thead><tr>
          <th scope="col">SHA-256</th><th scope="col">List</th><th scope="col">Note</th><th scope="col">Added</th><th scope="col">Remove</th>
        </tr></thead><tbody>
        {entries.data.items.map(entry => <tr key={entry.id} className={entry.list_kind === 'block' ? 'row-alert' : ''}>
          <td><code>{entry.sha256}</code></td>
          <td>{LABELS[entry.list_kind]}</td>
          <td className="cell-name" title={entry.note}>{entry.note || <span className="muted">None</span>}</td>
          <td><small>{new Date(entry.created_at * 1000).toISOString().replace('T', ' ').slice(0, 19)} UTC</small>
            <small>{entry.created_by || 'Unknown'}</small></td>
          <td className="cell-actions"><Button variant="destructive" disabled={busy} aria-label={`Remove ${entry.sha256}`}
            onClick={() => { setRemoved(''); setRemoval(entry) }}>Remove</Button></td>
        </tr>)}</tbody></table></div>}
      <div className="history-pagination"><Button variant="secondary" disabled={entries.isFetching || !params.get('before')} onClick={() => paginate()}>Newest entries</Button>
        <Button variant="secondary" disabled={entries.isFetching || !entries.data.next_before} onClick={() => paginate(entries.data!.next_before!)}>Older entries</Button></div>
    </>}

    <Dialog open={review !== null} locked={busy} onOpenChange={open => { if (!open && !busy) setReview(null) }}
      title={`Add to the ${review ? LABELS[review.kind].toLowerCase() : 'list'}?`}
      description={review?.kind === 'block' ? 'Later scans of these files will report a detection and a raised risk.'
        : 'Later scans will show an informational finding. This does not clear or allow these files.'}>
      <p>{review?.hashes.length} unique SHA-256 value{review?.hashes.length === 1 ? '' : 's'}{note.trim() ? ` · Note: ${note.trim()}` : ''}</p>
      <div className="report-actions"><Button variant="secondary" disabled={busy} onClick={() => setReview(null)}>Cancel</Button>
        <Button disabled={busy} onClick={() => { void add() }}>{busy ? 'Adding…' : 'Confirm addition'}</Button></div>
    </Dialog>
    <Dialog open={removal !== null} locked={busy} onOpenChange={open => { if (!open && !busy) setRemoval(null) }}
      title="Remove this hash?" description="Scans that run afterwards no longer match it. Completed results keep what they recorded.">
      <p><code className="hash-value">{removal?.sha256}</code></p><p>{removal ? LABELS[removal.list_kind] : ''}{removal?.note ? ` · ${removal.note}` : ''}</p>
      <div className="report-actions"><Button variant="secondary" disabled={busy} onClick={() => setRemoval(null)}>Cancel</Button>
        <Button variant="destructive" disabled={busy} onClick={() => { void remove() }}>{busy ? 'Removing…' : 'Confirm removal'}</Button></div>
    </Dialog>
  </section>
}
