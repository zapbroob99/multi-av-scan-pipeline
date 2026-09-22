import { useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import type { components } from '../lib/api.generated'
import { Button } from '../components/ui/button'
import { Dialog } from '../components/ui/dialog'

type Client = components['schemas']['ServiceClientSummary']
type Values = components['schemas']['ServiceClientUpdate']
type Change = { id: number; key: string; values: Values }

function ClientCard({ client, disabled, review }: { client: Client; disabled: boolean; review: (change: Change) => void }) {
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    review({ id: client.id, key: client.client_key, values: { display_name: String(data.get('display_name') || ''), enabled: data.get('enabled') === 'enabled' } })
  }
  return <article className="submission-card report-engine"><h2>{client.display_name}</h2><p className="muted">#{client.id} · {client.client_key} · {client.enabled ? 'Enabled' : 'Disabled'}</p>
    <Link to={`/service-clients/${client.id}/profiles`}>Profile routing</Link>{' ? '}<Link to={`/service-clients/${client.id}/credentials`}>Credentials</Link>
    {client.managed && <p>Managed compatibility client. Edit deployment configuration through the existing administration workflow.</p>}
    {client.metadata_incomplete && <p role="alert">Metadata exceeds the console limit. Use legacy administration to review the complete values before editing.</p>}
    <form onSubmit={submit} aria-label={`Edit client ${client.id}`}><fieldset disabled={disabled || client.managed || client.metadata_incomplete}>
      <label>Display name<input name="display_name" required maxLength={100} defaultValue={client.display_name} /></label>
      <label>Client state<select name="enabled" defaultValue={client.enabled ? 'enabled' : 'disabled'}><option value="enabled">Enabled</option><option value="disabled">Disabled</option></select></label>
      <Button type="submit">Review client changes</Button></fieldset></form>
  </article>
}

export default function ServiceClients({ session }: { session: Session }) {
  const [params, setParams] = useSearchParams()
  const after = params.get('after') || ''
  const [confirmation, setConfirmation] = useState<Change | null>(null)
  const [needsRefresh, setNeedsRefresh] = useState(false)
  const clients = useQuery({ queryKey: ['service-clients', after], queryFn: ({ signal }) => request('/api/ui/v1/service-clients', 'get', {
    query: new URLSearchParams({ limit: '20', ...(after ? { after } : {}) }), signal }),
    retry: false, gcTime: 0, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })
  const action = useMutation({ retry: false, mutationFn: (change: Change) => request('/api/ui/v1/service-clients/{client_id}', 'put', {
    params: { client_id: change.id }, csrf: session.csrf_token, body: change.values }),
    onSettled: () => { setConfirmation(null); setNeedsRefresh(true) } })
  const busy = clients.isFetching || action.isPending || confirmation !== null
  return <section className="page management-page"><div className="page-heading"><div><p className="eyebrow">INTEGRATIONS</p><h1>Service clients</h1>
    <p className="muted">Review integration identities and manage their names and enabled state.</p></div>
    <Button variant="secondary" disabled={busy} onClick={async () => { action.reset(); const result = await clients.refetch(); if (!result.error) setNeedsRefresh(false) }}>Refresh clients</Button></div>
    <p className="callout">Disabling a client can prevent API/ICAP submissions. Accepted scan routing snapshots are not rewritten and credentials are not revoked.
      Enabled status alone does not establish a valid default profile or credential. Coordinate concurrent edits; the last successful save wins.</p>
    <Link to="/service-clients/new">Create service client</Link>
    {clients.isPending && <p role="status">Loading service clients…</p>}
    {clients.error && <p role="alert" className="error">{clients.error.message}</p>}
    {action.isSuccess && <p role="status" className="callout">Service client updated. Refresh clients to see the current state.</p>}
    {action.error && <p role="alert" className="error">{action.error.message} The request may have reached the server. Refresh and reconcile before saving again; no automatic retry is performed.</p>}
    {needsRefresh && <p>Refresh clients before editing another record.</p>}
    {!needsRefresh && !clients.error && clients.data && <>
      {!clients.data.items.length && <p>No service clients on this page.</p>}
      {clients.data.items.map(client => <ClientCard key={`${client.id}-${clients.dataUpdatedAt}`} client={client} disabled={busy} review={setConfirmation} />)}
      <div className="history-pagination"><Button variant="secondary" disabled={busy || !after} onClick={() => setParams({})}>First clients</Button>
        <Button variant="secondary" disabled={busy || !clients.data.next_after} onClick={() => setParams({ after: String(clients.data!.next_after) })}>Next clients</Button></div>
    </>}
    <Dialog open={confirmation !== null} onOpenChange={open => { if (!open && !action.isPending) setConfirmation(null) }} title="Update service client?"
      description={`Set ${confirmation?.key || ''} to ${confirmation?.values.display_name || ''}, ${confirmation?.values.enabled ? 'enabled' : 'disabled'}. Disabling can prevent integration submissions. No credentials are revoked.`}>
      <div className="report-actions"><Button variant="secondary" disabled={action.isPending} onClick={() => setConfirmation(null)}>Cancel</Button>
        <Button disabled={action.isPending} onClick={() => { if (confirmation) action.mutate(confirmation) }}>{action.isPending ? 'Saving…' : 'Confirm client changes'}</Button></div>
    </Dialog>
  </section>
}
