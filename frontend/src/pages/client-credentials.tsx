import { useContext, useEffect, useRef, useState, type FormEvent } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ArrowLeft, Cpu, KeyRound, RefreshCw } from 'lucide-react'
import { request, type Session } from '../lib/api'
import { Button } from '../components/ui/button'
import { Dialog } from '../components/ui/dialog'
import { ClientNavigation } from '../components/client-navigation'
import { ClientWorkspace, useClientPanelGuard } from '../components/client-workspace'

type Review = { credential_label: string; client_key: string; display_name: string; profile_name: string; engine_ids: number[] }

export default function ClientCredentials({ session, create = false }: { session: Session; create?: boolean }) {
  const routeClientId = useParams().clientId
  const workspace = useContext(ClientWorkspace)
  const clientId = workspace?.clientId ?? Number(routeClientId)
  const secret = useRef<HTMLInputElement>(null)
  const [after, setAfter] = useState<number | null>(null)
  const [review, setReview] = useState<Review | null>(null)
  const [revokeId, setRevokeId] = useState<number | null>(null)
  const [busy, setBusy] = useState(false)
  const [locked, setLocked] = useState(false)
  const [message, setMessage] = useState('')
  const [failed, setFailed] = useState(false)
  const [createdId, setCreatedId] = useState<number | null>(null)
  useClientPanelGuard('credentials', busy || review !== null || revokeId !== null)
  useEffect(() => {
    if (workspace && workspace.tab !== 'credentials' && secret.current) secret.current.value = ''
  }, [workspace?.tab])
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
  return <section className="page management-page client-page">
    {create ? <Link className="client-back client-create-back" to="/service-clients"><ArrowLeft size={15} aria-hidden="true" />All service clients</Link> : <ClientNavigation clientId={clientId} />}
    <div className="page-heading"><div><p className="eyebrow">INTEGRATIONS{!create && ` · CLIENT #${clientId}`}</p>
    <h1>{create ? 'Create service client' : 'Client credentials'}</h1><p className="muted">{create ? 'Set up an integration identity, its scan engines and API access.' : 'Manage API access for this client. Tokens are never displayed after saving.'}</p></div></div>
    {message && <p role={failed ? 'alert' : 'status'} className={failed ? 'error' : 'callout'}>{message}</p>}
    {createdId && <Link to={`/service-clients/${createdId}/credentials`}>Manage created client credentials</Link>}
    {create && locked && !createdId && <Link to="/service-clients">Review clients before trying again</Link>}
    {(options.error || credentials.error) && <p role="alert">Unable to load current configuration. Refresh before continuing.</p>}
    {create && options.data?.incomplete && <p role="alert">More than 100 engine instances exist, beyond what this editor can show. Assign engines after creation from the client's profile routing.</p>}
    <div className={`client-credentials-layout ${create ? 'client-create-layout' : ''}`}>
    <form onSubmit={prepare} className="submission-card client-credential-form"><fieldset disabled={disabled}>
      <legend className="client-form-title">{create ? 'Client and initial credential' : 'Add credential'}</legend>
      {create && <><section className="client-form-section"><h2><span className="client-step">1</span>Integration identity</h2>
        <p className="muted client-note">Use a stable key for configuration and a recognizable name for your team.</p><div className="field-grid">
        <label>Client key<input name="client_key" required minLength={2} maxLength={64} pattern="[a-z0-9][a-z0-9_-]{1,63}" placeholder="e.g. document-gateway" /></label>
        <label>Display name<input name="display_name" required maxLength={100} placeholder="e.g. Document Gateway" /></label></div></section>
        <section className="client-form-section"><h2><span className="client-step">2</span>Scan routing</h2>
        <label>Default profile name<input name="profile_name" required maxLength={100} placeholder="e.g. Standard scanning" /></label>
        <fieldset><legend>Required engine instances</legend><div className="client-engine-options">{options.data?.engines.map(engine => <label className="client-engine-option" key={engine.id}>
          <input type="checkbox" name="engine_ids" value={engine.id} /><Cpu size={18} aria-hidden="true" /><span><strong>{engine.display_name}</strong><small>#{engine.id}{engine.enabled ? '' : ' · disabled'}</small></span></label>)}</div></fieldset>
        <p className="muted client-note">Choose at least one engine. Disabled or source-ineligible engines remain excluded at intake.</p></section></>}
      <section className="client-form-section">{create && <h2><span className="client-step">3</span>API access</h2>}
      <label>Credential label<input name="credential_label" required maxLength={100} placeholder="e.g. Gateway production" /></label>
      <label>API token<input ref={secret} type="password" required minLength={32} maxLength={512} autoComplete="new-password" aria-describedby="client-token-help" /></label>
      <p id="client-token-help" className="muted client-note">Supply a securely generated token of 32–512 non-whitespace characters. Keep your copy securely: MASP never returns the token.</p>
      </section><div className="client-form-footer"><Button type="submit">Review {create ? 'client creation' : 'credential'}</Button></div>
    </fieldset></form>
    {create && <aside className="submission-card client-onboarding"><span className="client-icon"><KeyRound size={22} aria-hidden="true" /></span><h2>Ready to connect</h2>
      <p className="muted">The client, default profile and first credential are saved together after your confirmation.</p>
      <ol><li>Name the integration that will submit files.</li><li>Choose the engines required for its scans.</li><li>Save a token you can configure in that system.</li></ol>
      <p className="muted client-note">After creation, open Connect to review readiness and find the API endpoints and ICAP setting.</p></aside>}
    {!create && <section className="client-credential-list" aria-label="Saved credentials"><div className="client-section-heading"><h2>Saved credentials</h2><Button variant="secondary" disabled={busy || review !== null || revokeId !== null} onClick={async () => {
      const result = await credentials.refetch(); if (!result.error) { setLocked(false); setMessage('') }
    }}><RefreshCw size={14} aria-hidden="true" />Refresh credentials</Button></div>
      <p className="muted client-note">Credentials require an enabled client and valid routing. Revocation blocks subsequent authentication; accepted scans are preserved.</p>
      {credentials.isPending && <p role="status">Loading credentials…</p>}
      {!credentials.error && credentials.data?.items.map(item => <article className="submission-card" key={item.id}>
        <div className="client-section-heading"><div className="client-identity"><KeyRound size={18} aria-hidden="true" /><h2>{item.label}</h2></div>
          <span className={`client-badge ${item.revoked_at === null ? 'client-badge-enabled' : ''}`}>{item.revoked_at === null ? 'Active' : 'Revoked'}</span></div>
        <dl className="client-credential-metadata"><div><dt>Credential</dt><dd>#{item.id}</dd></div><div><dt>Created</dt><dd>{item.created_at}</dd></div>
        <div><dt>Last used</dt><dd>{item.last_used_at === null ? 'Never recorded' : new Date(item.last_used_at * 1000).toLocaleString()}</dd></div></dl>
        <div className="client-form-footer"><Button variant="destructive" disabled={disabled || item.revoked_at !== null} onClick={() => setRevokeId(item.id)}>Revoke credential #{item.id}</Button></div></article>)}
      {credentials.data?.items.length === 0 && <div className="empty"><KeyRound size={26} aria-hidden="true" /><h2>No credentials on this page.</h2><p>Add a credential to configure API access.</p></div>}
      <div className="history-pagination"><Button disabled={busy || locked || review !== null || revokeId !== null || after === null} onClick={() => setAfter(null)}>First credentials</Button>
        <Button disabled={busy || locked || review !== null || revokeId !== null || !credentials.data?.next_after} onClick={() => setAfter(credentials.data!.next_after)}>Next credentials</Button></div></section>}
    </div>
    <Dialog open={review !== null || revokeId !== null} onOpenChange={open => { if (!open) cancel() }} title={review ? 'Save credential?' : 'Revoke credential?'}
      description={review ? `Save ${review.credential_label} for ${create ? review.display_name : `client #${clientId}`}${create ? ` with required engine IDs ${review.engine_ids.join(', ') || '(none selected)'}` : ''}? The token will not be shown again.` : `Revoke credential #${revokeId} for client #${clientId}? Subsequent authentication with it will fail.`}>
      <div className="report-actions"><Button variant="secondary" disabled={busy} onClick={cancel}>Cancel</Button>
        <Button disabled={busy || (create && !!review && !review.engine_ids.length)} onClick={submit}>{busy ? 'Saving…' : 'Confirm'}</Button></div>
    </Dialog>
  </section>
}
