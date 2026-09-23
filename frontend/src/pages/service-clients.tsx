import { lazy, Suspense, useCallback, useRef, useState, type FormEvent, type KeyboardEvent } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Cable, ChevronRight, Database, GitBranch, KeyRound, Plus, RefreshCw, Settings2 } from 'lucide-react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import type { components } from '../lib/api.generated'
import { Button } from '../components/ui/button'
import { Dialog } from '../components/ui/dialog'
import { ClientWorkspace, type ClientTab } from '../components/client-workspace'

const ClientSetup = lazy(() => import('./client-setup'))
const ClientProfiles = lazy(() => import('./client-profiles'))
const ClientStorage = lazy(() => import('./client-storage'))
const ClientCredentials = lazy(() => import('./client-credentials'))
type Client = components['schemas']['ServiceClientSummary']
type Values = components['schemas']['ServiceClientUpdate']
const tabs = [
  { key: 'settings', label: 'Settings', icon: Settings2 },
  { key: 'setup', label: 'Connection', icon: Cable },
  { key: 'profiles', label: 'Profile routing', icon: GitBranch },
  { key: 'storage', label: 'Storage', icon: Database },
  { key: 'credentials', label: 'Credentials', icon: KeyRound },
] as const

function ClientEditor({ client, session, close, updated }: { client: Client; session: Session; close: () => void; updated: () => void }) {
  const [tab, setTab] = useState<ClientTab>('settings')
  const [visited, setVisited] = useState<Set<ClientTab>>(() => new Set(['settings']))
  const [guards, setGuards] = useState<Record<string, boolean>>({})
  const guard = useCallback((panel: string, blocked: boolean) => setGuards(current => current[panel] === blocked ? current : { ...current, [panel]: blocked }), [])
  const [confirmation, setConfirmation] = useState<Values | null>(null)
  const [needsRefresh, setNeedsRefresh] = useState(false)
  const action = useMutation({ retry: false, mutationFn: (values: Values) => request('/api/ui/v1/service-clients/{client_id}', 'put', {
    params: { client_id: client.id }, csrf: session.csrf_token, body: values }),
    onSettled: () => { setConfirmation(null); setNeedsRefresh(true); updated() } })
  const blocked = action.isPending || confirmation !== null || Object.values(guards).some(Boolean)
  function select(next: ClientTab) {
    if (blocked) return
    setVisited(current => new Set([...current, next]))
    setTab(next)
    requestAnimationFrame(() => document.getElementById(`client-tab-${next}`)?.focus())
  }
  function tabKey(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    const next = event.key === 'ArrowRight' ? (index + 1) % tabs.length : event.key === 'ArrowLeft' ? (index + tabs.length - 1) % tabs.length : event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : null
    if (next === null || blocked) return
    event.preventDefault()
    select(tabs[next].key)
    document.getElementById(`client-tab-${tabs[next].key}`)?.focus()
  }
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    setConfirmation({ display_name: String(data.get('display_name') || ''), enabled: data.get('enabled') === 'enabled' })
  }
  return <Dialog open onOpenChange={open => { if (!open && !blocked) close() }} locked={blocked}
    className="client-dialog client-page" title={client.display_name} description={`${client.client_key} · Client #${client.id}`}>
    <ClientWorkspace.Provider value={{ clientId: client.id, tab, select, guard }}>
      <div className="client-modal-tabs" role="tablist" aria-label="Client settings">
        {tabs.map(({ key, label, icon: Icon }, index) => <button key={key} type="button" role="tab" id={`client-tab-${key}`} aria-selected={tab === key}
          aria-controls={`client-panel-${key}`} tabIndex={tab === key ? 0 : -1} disabled={blocked} onClick={() => select(key)} onKeyDown={event => tabKey(event, index)}>
          <Icon size={16} aria-hidden="true" />{label}</button>)}
      </div>
      {tabs.map(({ key, label }) => <div key={key} role="tabpanel" id={`client-panel-${key}`} aria-labelledby={`client-tab-${key}`} hidden={tab !== key} tabIndex={0} className="client-modal-panel">
        {visited.has(key) && <Suspense fallback={<p role="status">Loading {label.toLowerCase()}…</p>}>
          {key === 'settings' && <section className="client-general-settings">
            <div className="client-section-heading"><div><h2>General settings</h2><p className="muted">Manage this integration's display name and submission access.</p></div>
              <span className="client-badge">{client.managed ? 'Deployment managed' : needsRefresh ? 'Refresh required' : client.enabled ? 'Enabled' : 'Disabled'}</span></div>
            {client.managed && <p className="callout">Managed compatibility client. Edit deployment configuration through the existing administration workflow.</p>}
            {client.metadata_incomplete && <p role="alert" className="error">Metadata exceeds the console limit. Use legacy administration to review the complete values before editing.</p>}
            {action.isSuccess && <p role="status" className="callout">Service client updated. Close this window and refresh clients to see the current state.</p>}
            {action.error && <p role="alert" className="error">{action.error.message} The request may have reached the server. Close this window and refresh clients before saving again; no automatic retry is performed.</p>}
            {!needsRefresh && <form onSubmit={submit} aria-label={`Edit client ${client.id}`}><fieldset disabled={blocked || client.managed || client.metadata_incomplete}>
              <div className="field-grid"><label>Display name<input name="display_name" required maxLength={100} defaultValue={client.display_name} /></label>
                <label>Client state<select name="enabled" defaultValue={client.enabled ? 'enabled' : 'disabled'}><option value="enabled">Enabled</option><option value="disabled">Disabled</option></select></label></div>
              <p className="muted client-note">Disabling prevents new submissions. Existing scans and credentials are preserved. Concurrent edits use the last successful save.</p>
              <div className="client-form-footer"><Button type="submit">Review client changes</Button></div>
            </fieldset></form>}
          </section>}
          {key === 'setup' && <ClientSetup />}
          {key === 'profiles' && <ClientProfiles session={session} />}
          {key === 'storage' && <ClientStorage session={session} />}
          {key === 'credentials' && <ClientCredentials session={session} />}
        </Suspense>}
      </div>)}
      <Dialog open={confirmation !== null} onOpenChange={open => { if (!open && !action.isPending) setConfirmation(null) }} locked={action.isPending} title="Update service client?"
        description={`Set ${client.client_key} to ${confirmation?.display_name || ''}, ${confirmation?.enabled ? 'enabled' : 'disabled'}. Disabling can prevent integration submissions. No credentials are revoked.`}>
        <div className="report-actions"><Button variant="secondary" disabled={action.isPending} onClick={() => setConfirmation(null)}>Cancel</Button>
          <Button disabled={action.isPending} onClick={() => { if (confirmation) action.mutate(confirmation) }}>{action.isPending ? 'Saving…' : 'Confirm client changes'}</Button></div>
      </Dialog>
    </ClientWorkspace.Provider>
  </Dialog>
}

export default function ServiceClients({ session }: { session: Session }) {
  const [params, setParams] = useSearchParams()
  const after = params.get('after') || ''
  const [selected, setSelected] = useState<Client | null>(null)
  const [needsRefresh, setNeedsRefresh] = useState(false)
  const opener = useRef<HTMLButtonElement | null>(null)
  const refresh = useRef<HTMLButtonElement | null>(null)
  const clients = useQuery({ queryKey: ['service-clients', after], queryFn: ({ signal }) => request('/api/ui/v1/service-clients', 'get', {
    query: new URLSearchParams({ limit: '20', ...(after ? { after } : {}) }), signal }),
    retry: false, gcTime: 0, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })
  const busy = clients.isFetching || selected !== null
  return <section className="page management-page client-page"><div className="page-heading"><div><p className="eyebrow">INTEGRATIONS</p><h1>Service clients</h1>
    <p className="muted">Select a client to manage its settings and integration access.</p></div><div className="client-heading-actions">
    <Button ref={refresh} variant="secondary" disabled={busy} onClick={async () => { const result = await clients.refetch(); if (!result.error) setNeedsRefresh(false) }}><RefreshCw size={14} aria-hidden="true" />Refresh clients</Button>
    <Link className="button button-primary" to="/service-clients/new"><Plus size={16} aria-hidden="true" />Create service client</Link></div></div>
    {clients.isPending && <p role="status">Loading service clients…</p>}
    {clients.error && <p role="alert" className="error">{clients.error.message}</p>}
    {needsRefresh && <p role="status" className="callout">Refresh clients to load current settings before editing another record.</p>}
    {!needsRefresh && !clients.error && clients.data && <>
      <div className="client-list-heading"><h2>Integration directory <span className="client-badge">{clients.data.items.length} on this page</span></h2>
        <p className="muted">Enabled state does not prove connection readiness.</p></div>
      {!clients.data.items.length && <div className="empty"><Cable size={28} aria-hidden="true" /><h2>No service clients on this page.</h2><p>Create a client or return to the first page.</p></div>}
      <ul className="client-list">{clients.data.items.map(client => <li key={client.id}>
        <button type="button" className="client-list-row" disabled={clients.isFetching} aria-label={`Manage ${client.display_name}`} onClick={event => { opener.current = event.currentTarget; setSelected(client) }}>
          <span className="client-icon"><Cable size={20} aria-hidden="true" /></span><span className="client-list-identity"><strong>{client.display_name}</strong><span className="muted"><code>{client.client_key}</code> · #{client.id}</span></span>
          <span className="client-badges">{client.managed && <span className="client-badge">Managed</span>}<span className={`client-badge ${client.enabled ? 'client-badge-enabled' : ''}`}>{client.enabled ? 'Enabled' : 'Disabled'}</span></span>
          <ChevronRight size={18} aria-hidden="true" />
        </button>
      </li>)}</ul>
      <div className="history-pagination"><Button variant="secondary" disabled={busy || !after} onClick={() => setParams({})}>First clients</Button>
        <Button variant="secondary" disabled={busy || !clients.data.next_after} onClick={() => setParams({ after: String(clients.data!.next_after) })}>Next clients</Button></div>
    </>}
    {selected && <ClientEditor key={selected.id} client={selected} session={session} updated={() => setNeedsRefresh(true)} close={() => {
      setSelected(null)
      requestAnimationFrame(() => { (needsRefresh ? refresh.current : opener.current)?.focus() })
    }} />}
  </section>
}
