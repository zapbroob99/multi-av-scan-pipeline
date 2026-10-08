import { ErrorMessage } from '../components/error-message'
import { useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import type { components } from '../lib/api.generated'
import { Button } from '../components/ui/button'
import { Dialog } from '../components/ui/dialog'
import { Timestamp } from '../components/timestamp'
import { EXPIRY } from '../components/exception-dialog'

type Item = components['schemas']['ExceptionItem']
type Draft = components['schemas']['ExceptionCreate']

const SHA256 = /^[0-9a-f]{64}$/
const STATES = ['active', 'expired', 'revoked', 'all'] as const
const STATE_LABELS: Record<string, string> = { active: 'Active', expired: 'Expired', revoked: 'Revoked' }

function scopeLabel(item: Pick<Item, 'client_id' | 'client_name'>) {
  return item.client_id === null ? 'All clients and manual scans' : `#${item.client_id} ${item.client_name || 'Name unavailable'}`
}

export default function Exceptions({ session }: { session: Session }) {
  const queryClient = useQueryClient()
  const [params, setParams] = useSearchParams()
  // `add` and `client` only prefill the form (from a scan report); the list ignores them.
  const query = new URLSearchParams()
  for (const key of ['q', 'state', 'before']) { const value = params.get(key); if (value) query.set(key, value) }
  query.set('limit', '20')
  const items = useQuery({ queryKey: ['exceptions', query.toString()],
    queryFn: ({ signal }) => request('/api/ui/v1/exceptions', 'get', { query, signal }),
    retry: false, staleTime: 0, gcTime: 0, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })
  const clients = useQuery({ queryKey: ['ledger-clients'], queryFn: ({ signal }) => request('/api/ui/v1/api-ledger/clients', 'get', { signal }),
    retry: false, staleTime: 60000, gcTime: 300000, refetchOnWindowFocus: false })

  const [sha256, setSha256] = useState(() => (params.get('add') || '').trim().toLowerCase())
  const [client, setClient] = useState(() => /^\d+$/.test(params.get('client') || '') ? params.get('client')! : '')
  const [reason, setReason] = useState('')
  const [expiry, setExpiry] = useState('')
  const [review, setReview] = useState<Draft | null>(null)
  const [revocation, setRevocation] = useState<Item | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  function refresh() { void queryClient.invalidateQueries({ queryKey: ['exceptions'] }) }
  function clientName(id: string) {
    const choice = clients.data?.items.find(row => String(row.id) === id)
    return choice ? `#${choice.id} ${choice.display_name}` : `Client #${id}`
  }
  function prepare(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError(''); setNotice('')
    const digest = sha256.trim().toLowerCase()
    if (!SHA256.test(digest)) { setError("Enter the file's full SHA-256 (64 hexadecimal characters)."); return }
    if (!reason.trim()) { setError('A reason is required.'); return }
    setReview({ sha256: digest, reason: reason.trim(), service_client_id: client ? Number(client) : null,
      expires_in_days: expiry ? Number(expiry) : null })
  }
  async function add() {
    if (!review) return
    setBusy(true); setError('')
    try {
      // No automatic retry: an uncertain outcome is resolved by reading the list again.
      const created = await request('/api/ui/v1/exceptions', 'post', { csrf: session.csrf_token, body: review })
      setNotice(`Exception #${created.id} added. The file is allowed the next time it is sent; earlier scans keep their decisions.`)
      setSha256(''); setReason(''); setExpiry(''); setClient('')
      if (params.get('add') || params.get('client')) {
        const next = new URLSearchParams(params); next.delete('add'); next.delete('client'); setParams(next)
      }
    } catch (e) { setError(`${(e as Error).message} Refresh the list to see what was stored.`) }
    finally { setBusy(false); setReview(null); refresh() }
  }
  async function revoke() {
    if (!revocation) return
    setBusy(true); setError(''); setNotice('')
    try {
      await request('/api/ui/v1/exceptions/{exception_id}/revoke', 'post', { params: { exception_id: revocation.id }, csrf: session.csrf_token })
      setNotice(`Exception #${revocation.id} revoked. The file is judged normally the next time it is sent.`)
    } catch (e) { setError((e as Error).message) }
    finally { setBusy(false); setRevocation(null); refresh() }
  }
  function filter(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget), next = new URLSearchParams()
    const q = String(form.get('q') || '').trim(), state = String(form.get('state') || 'active')
    if (q) next.set('q', q)
    if (state !== 'active') next.set('state', state)
    setParams(next)
  }
  function paginate(before?: number) {
    const next = new URLSearchParams(params)
    if (before) next.set('before', String(before)); else next.delete('before')
    setParams(next)
  }

  return <section className="page management-page">
    <div className="page-heading"><div><p className="eyebrow">ENGINES</p><h1>Exceptions</h1>
      <p className="muted">Let one exact file through after you have confirmed it is harmless.</p></div>
      <Button variant="secondary" disabled={items.isFetching} onClick={refresh}>Refresh list</Button></div>
    <p className="callout">An exception names a file by its SHA-256 and allows it whatever found it: an engine detection, a profile rule
      or an archive check. Engines still run and their results are kept as evidence, but the decision is "Allow (exception)" and no
      detection alert or SIEM event is raised. It applies to files sent after it is added; earlier scans keep their decisions.
      A client's own exception is used before one for all clients. Files inside an archive need their own exception.
      The hash list's allowlist is different: it is informational and never allows a file.</p>

    <form onSubmit={prepare} className="submission-card" aria-label="Add an exception">
      <h2>Add an exception</h2>
      <label>SHA-256<input value={sha256} maxLength={128} spellCheck={false} autoComplete="off" onChange={e => setSha256(e.target.value)} /></label>
      <label>Applies to<select value={client} onChange={e => setClient(e.target.value)} disabled={!clients.data && !clients.error}>
        <option value="">All clients and manual scans</option>
        {clients.data?.items.map(choice => <option key={choice.id} value={choice.id}>{choice.display_name} ({choice.client_key}) · #{choice.id}</option>)}
        {client && !clients.data?.items.some(choice => String(choice.id) === client) && <option value={client}>Client #{client}</option>}
      </select></label>
      <label>Reason<input value={reason} maxLength={500} required onChange={e => setReason(e.target.value)} aria-describedby="exception-reason-help" /></label>
      <p id="exception-reason-help" className="muted">Why this file is harmless, for example the ticket or the vendor confirmation. Shown on every scan it allows.</p>
      <label>Expires<select value={expiry} onChange={e => setExpiry(e.target.value)}>
        {EXPIRY.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
      <Button type="submit" disabled={busy}>Review exception</Button>
    </form>

    {error && <p role="alert" className="error hash-value"><ErrorMessage message={error} /></p>}
    {notice && <p className="notice" role="status">{notice}</p>}

    <form key={params.toString()} onSubmit={filter} className="submission-card" aria-label="Exception filters"><fieldset className="history-filters">
      <label>SHA-256 or reason<input name="q" maxLength={200} defaultValue={params.get('q') || ''} /></label>
      <label>State<select name="state" defaultValue={params.get('state') || 'active'}>
        {STATES.map(state => <option key={state} value={state}>{state === 'all' ? 'All' : STATE_LABELS[state]}</option>)}</select></label>
      <Button type="submit" disabled={items.isFetching}>Apply filters</Button>
      <Button type="button" variant="secondary" onClick={() => setParams({})}>Reset filters</Button>
    </fieldset></form>

    {items.isPending && <p role="status">Loading exceptions…</p>}
    {items.error && <p role="alert" className="error"><ErrorMessage message={items.error.message || ''} /></p>}
    {!items.error && items.data && <>
      {!items.data.items.length && <p className="empty">No exceptions match these filters.</p>}
      {items.data.items.length > 0 && <div className="history-table-wrap" role="region" aria-label="Exceptions" tabIndex={0}>
        <table className="history-table compact-table"><thead><tr>
          <th scope="col">SHA-256</th><th scope="col">Applies to</th><th scope="col">Reason</th><th scope="col">Added</th>
          <th scope="col">Expires</th><th scope="col">State</th><th scope="col">Files allowed</th><th scope="col">Revoke</th>
        </tr></thead><tbody>
        {items.data.items.map(item => <tr key={item.id}>
          <td><small className="muted">#{item.id}</small> <code>{item.sha256}</code></td>
          <td className="cell-name">{scopeLabel(item)}</td>
          <td className="cell-name" title={item.reason}>{item.reason}</td>
          <td><small><Timestamp value={item.created_at} /></small><small>{item.created_by}</small></td>
          <td>{item.expires_at === null ? <span className="muted">Never</span> : <small><Timestamp value={item.expires_at} /></small>}</td>
          <td>{STATE_LABELS[item.state] || item.state}{item.revoked_at !== null && <small>{item.revoked_by || 'Unknown'}, <Timestamp value={item.revoked_at} /></small>}</td>
          <td>{item.uses > 0 ? <Link to={`/api-ledger?q=${item.sha256}`}>{item.uses.toLocaleString()}</Link> : '0'}</td>
          <td className="cell-actions">{item.state === 'active' && <Button variant="destructive" disabled={busy} aria-label={`Revoke exception ${item.id}`}
            onClick={() => { setNotice(''); setRevocation(item) }}>Revoke</Button>}</td>
        </tr>)}</tbody></table></div>}
      {Boolean(params.get('before') || items.data.next_before) && <div className="history-pagination">
        <Button variant="secondary" disabled={items.isFetching || !params.get('before')} onClick={() => paginate()}>Newest exceptions</Button>
        <Button variant="secondary" disabled={items.isFetching || !items.data.next_before} onClick={() => paginate(items.data!.next_before!)}>Older exceptions</Button></div>}
    </>}

    <Dialog open={review !== null} locked={busy} onOpenChange={open => { if (!open && !busy) setReview(null) }}
      title="Allow this file by exception?"
      description="Every later copy of this exact file is allowed for the scope below, even when an engine detects it. No detection alert is raised for it.">
      <p><code className="hash-value">{review?.sha256}</code></p>
      <p>Applies to: {review?.service_client_id ? clientName(String(review.service_client_id)) : 'All clients and manual scans'}</p>
      <p>Expires: {EXPIRY.find(([value]) => value === String(review?.expires_in_days ?? ''))?.[1]}</p>
      <p>Reason: {review?.reason}</p>
      <div className="report-actions"><Button variant="secondary" disabled={busy} onClick={() => setReview(null)}>Cancel</Button>
        <Button disabled={busy} onClick={() => { void add() }}>{busy ? 'Adding…' : 'Confirm exception'}</Button></div>
    </Dialog>
    <Dialog open={revocation !== null} locked={busy} onOpenChange={open => { if (!open && !busy) setRevocation(null) }}
      title="Revoke this exception?" description="The file is judged normally the next time it is sent. Scans it already allowed keep their decisions.">
      <p><code className="hash-value">{revocation?.sha256}</code></p>
      <p>{revocation ? scopeLabel(revocation) : ''} · {revocation?.reason}</p>
      <div className="report-actions"><Button variant="secondary" disabled={busy} onClick={() => setRevocation(null)}>Cancel</Button>
        <Button variant="destructive" disabled={busy} onClick={() => { void revoke() }}>{busy ? 'Revoking…' : 'Confirm revocation'}</Button></div>
    </Dialog>
  </section>
}
