import { useRef, useState, type FormEvent } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import { Button } from '../components/ui/button'
import { Dialog } from '../components/ui/dialog'

type Review = { credential_label: string; client_key: string; display_name: string; profile_name: string; engine_ids: number[] }

export default function ClientCredentials({ session, create = false }: { session: Session; create?: boolean }) {
  const clientId = Number(useParams().clientId)
  const secret = useRef<HTMLInputElement>(null)
  const [after, setAfter] = useState<number | null>(null)
  const [review, setReview] = useState<Review | null>(null)
  const [revokeId, setRevokeId] = useState<number | null>(null)
  const [busy, setBusy] = useState(false)
  const [locked, setLocked] = useState(false)
  const [message, setMessage] = useState('')
  const [failed, setFailed] = useState(false)
  const [createdId, setCreatedId] = useState<number | null>(null)
  const options = useQuery({ queryKey: ['client-create-options'], enabled: create,
    queryFn: ({ signal }) => request('/api/ui/v1/service-clients/create-options', 'get', { signal }), retry: false, gcTime: 0, refetchOnWindowFocus: false })
  const credentials = useQuery({ queryKey: ['client-credentials', clientId, after], enabled: !create,
    queryFn: ({ signal }) => request('/api/ui/v1/service-clients/{client_id}/credentials', 'get', {
      params: { client_id: clientId }, query: new URLSearchParams(after ? { after: String(after) } : {}), signal }),
    retry: false, gcTime: 0, refetchOnWindowFocus: false, refetchOnReconnect: false })
  function prepare(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    // Read only public fields into React state. The password stays in its input until confirmation.
    const form = event.currentTarget
    const value = (name: string) => (form.elements.namedItem(name) as HTMLInputElement | null)?.value || ''
    setReview({ credential_label: value('credential_label'), client_key: value('client_key'), display_name: value('display_name'),
      profile_name: value('profile_name'), engine_ids: Array.from(form.querySelectorAll<HTMLInputElement>('input[name="engine_ids"]:checked')).map(input => Number(input.value)) })
  }
  function cancel() { if (!busy) { setReview(null); setRevokeId(null); if (secret.current) secret.current.value = '' } }
  async function submit() {
    if (busy || (!review && revokeId === null)) return
    setBusy(true); setFailed(false); setMessage('')
    try {
      if (review) {
        const api_token = secret.current?.value || ''
        if (secret.current) secret.current.value = ''
        // Direct transport deliberately avoids retaining secrets as query/mutation variables.
        if (create) {
          const result = await request('/api/ui/v1/service-clients', 'post', { csrf: session.csrf_token, body: { ...review, api_token } })
          setCreatedId(result.client_id); setMessage(`Client #${result.client_id} created with credential #${result.credential_id}.`)
        } else {
          const result = await request('/api/ui/v1/service-clients/{client_id}/credentials', 'post', {
            params: { client_id: clientId }, csrf: session.csrf_token, body: { credential_label: review.credential_label, api_token } })
          setMessage(`Credential #${result.credential_id} created. Refresh credentials to review it.`)
        }
      } else {
        await request('/api/ui/v1/service-clients/{client_id}/credentials/{credential_id}/revoke', 'post', {
          params: { client_id: clientId, credential_id: revokeId! }, csrf: session.csrf_token })
        setMessage('Credential revoked. Refresh credentials to review its status.')
      }
    } catch {
      setFailed(true); setMessage('Request failed or its outcome is uncertain. Refresh and reconcile before another attempt. No automatic retry is performed.')
    } finally { setBusy(false); setLocked(true); setReview(null); setRevokeId(null); if (secret.current) secret.current.value = '' }
  }
  const disabled = busy || locked || review !== null || revokeId !== null || (create ? !options.data || !!options.error || options.isFetching || options.data.incomplete : !credentials.data || credentials.isFetching || !!credentials.error)
  return <section className="page management-page"><div className="page-heading"><div><p className="eyebrow">INTEGRATIONS</p>
    <h1>{create ? 'Create service client' : 'Client credentials'}</h1>{!create && <p>Service client #{clientId}</p>}</div></div>
    <nav className="report-actions"><Link to="/service-clients">Service clients</Link>{!create && <Link to={`/service-clients/${clientId}/profiles`}>Profile routing</Link>}</nav>
    <p className="callout">Supply a securely generated token of 32–512 non-whitespace characters. Keep your copy securely: MASP never returns the token.
      Credentials require an enabled client and valid routing. Revocation blocks subsequent authentication; accepted scans are preserved.</p>
    {message && <p role={failed ? 'alert' : 'status'} className={failed ? 'error' : 'callout'}>{message}</p>}
    {createdId && <Link to={`/service-clients/${createdId}/credentials`}>Manage created client credentials</Link>}
    {create && locked && !createdId && <Link to="/service-clients">Review clients before trying again</Link>}
    {(options.error || credentials.error) && <p role="alert">Unable to load current configuration. Refresh before continuing.</p>}
    {create && options.data?.incomplete && <p role="alert">More than 100 engine instances exist. Use legacy administration to review complete routing.</p>}
    <form onSubmit={prepare} className="submission-card"><fieldset disabled={disabled}>
      <legend>{create ? 'Client and initial credential' : 'Add credential'}</legend>
      {create && <><label>Client key<input name="client_key" required minLength={2} maxLength={64} pattern="[a-z0-9][a-z0-9_-]{1,63}" /></label>
        <label>Display name<input name="display_name" required maxLength={100} /></label>
        <label>Default profile name<input name="profile_name" required maxLength={100} /></label>
        <fieldset><legend>Required engine instances</legend>{options.data?.engines.map(engine => <label className="report-engine" key={engine.id}>
          <input type="checkbox" name="engine_ids" value={engine.id} /> {engine.display_name} · #{engine.id}{engine.enabled ? '' : ' · disabled'}</label>)}</fieldset>
        <p>Choose at least one engine. Disabled or source-ineligible engines remain excluded at intake.</p></>}
      <label>Credential label<input name="credential_label" required maxLength={100} /></label>
      <label>API token<input ref={secret} type="password" required minLength={32} maxLength={512} autoComplete="new-password" /></label>
      <Button type="submit">Review {create ? 'client creation' : 'credential'}</Button>
    </fieldset></form>
    {!create && <><Button variant="secondary" disabled={busy || review !== null || revokeId !== null} onClick={async () => {
      const result = await credentials.refetch(); if (!result.error) { setLocked(false); setMessage('') }
    }}>Refresh credentials</Button>
      {credentials.isPending && <p role="status">Loading credentials…</p>}
      {!credentials.error && credentials.data?.items.map(item => <article className="submission-card" key={item.id}><h2>{item.label}</h2>
        <p>#{item.id} · {item.revoked_at === null ? 'Active' : 'Revoked'} · Created {item.created_at}</p>
        <p>Last used: {item.last_used_at === null ? 'Never recorded' : new Date(item.last_used_at * 1000).toLocaleString()}</p>
        <Button variant="secondary" disabled={disabled || item.revoked_at !== null} onClick={() => setRevokeId(item.id)}>Revoke credential #{item.id}</Button></article>)}
      {credentials.data?.items.length === 0 && <p>No credentials on this page.</p>}
      <div className="history-pagination"><Button disabled={busy || locked || review !== null || revokeId !== null || after === null} onClick={() => setAfter(null)}>First credentials</Button>
        <Button disabled={busy || locked || review !== null || revokeId !== null || !credentials.data?.next_after} onClick={() => setAfter(credentials.data!.next_after)}>Next credentials</Button></div></>}
    <Dialog open={review !== null || revokeId !== null} onOpenChange={open => { if (!open) cancel() }} title={review ? 'Save credential?' : 'Revoke credential?'}
      description={review ? `Save ${review.credential_label} for ${create ? review.display_name : `client #${clientId}`}${create ? ` with required engine IDs ${review.engine_ids.join(', ') || '(none selected)'}` : ''}? The token will not be shown again.` : `Revoke credential #${revokeId} for client #${clientId}? Subsequent authentication with it will fail.`}>
      <div className="report-actions"><Button variant="secondary" disabled={busy} onClick={cancel}>Cancel</Button>
        <Button disabled={busy || (create && !!review && !review.engine_ids.length)} onClick={submit}>{busy ? 'Saving…' : 'Confirm'}</Button></div>
    </Dialog>
  </section>
}
