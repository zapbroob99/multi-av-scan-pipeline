import { useContext, useState, type FormEvent } from 'react'
import { useParams } from 'react-router-dom'
import { Database, RefreshCw } from 'lucide-react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import type { components } from '../lib/api.generated'
import { Button } from '../components/ui/button'
import { Dialog } from '../components/ui/dialog'
import { ClientNavigation } from '../components/client-navigation'
import { ClientWorkspace, useClientPanelGuard } from '../components/client-workspace'

type Access = components['schemas']['ClientStorageAccess']
type Change = components['schemas']['StorageAccessUpdate']
type Grant = components['schemas']['StorageGrant']
type Draft = { access: 'none' | 'all' | 'prefixes'; prefixes: string }

function GrantSummary({ grants, backends }: { grants: Grant[]; backends: string[] }) {
  return grants.length ? <ul className="client-storage-summary">{grants.map(grant => <li key={grant.backend_key}>
    <strong>{grant.backend_key}</strong><span>{grant.access === 'all' ? 'Entire backend' : grant.prefixes?.join(', ')}
      {!backends.includes(grant.backend_key) && ' · Not configured on this server; access unavailable'}</span>
  </li>)}</ul> : <p className="muted">No backend access is granted.</p>
}

function StorageForm({ data, disabled, review }: { data: Access; disabled: boolean; review: (change: Change) => void }) {
  const [mode, setMode] = useState(data.mode)
  const [drafts, setDrafts] = useState<Record<string, Draft>>(() => Object.fromEntries(data.grants.map(grant =>
    [grant.backend_key, { access: grant.access, prefixes: grant.prefixes?.join('\n') || '' }])))
  const keys = [...new Set([...data.backends, ...data.grants.map(grant => grant.backend_key)])].sort()
  function update(key: string, value: Partial<Draft>) {
    setDrafts(current => ({ ...current, [key]: { ...(current[key] ?? { access: 'none', prefixes: '' }), ...value } }))
  }
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const grants: Grant[] = mode === 'environment' ? [] : keys.flatMap(key => {
      const draft = drafts[key]
      return !draft || draft.access === 'none' ? [] : [{ backend_key: key, access: draft.access,
        prefixes: draft.access === 'all' ? [] : draft.prefixes.split(/\r?\n/).map(prefix => prefix.trim()).filter(Boolean) }]
    })
    review({ mode, grants, expected_revision: data.revision, expected_environment_fingerprint: data.environment_fingerprint })
  }
  return <form onSubmit={submit}><fieldset disabled={disabled || data.managed}>
    <label>Access source<select value={mode} onChange={event => setMode(event.target.value as Access['mode'])}>
      <option value="environment">Deployment settings</option><option value="custom">Custom client access</option>
    </select></label>
    {mode === 'environment' ? <div className="submission-card"><h2>Deployment access</h2>
      <p className="muted">These grants come from the server configuration. Switch to custom access to manage this client here.</p>
      <GrantSummary grants={data.environment_grants} backends={data.backends} /></div>
      : <><p className="callout">Custom access replaces this client's deployment grants. Leave every backend at “No access” to deny all deferred storage access.</p>
        {!keys.length && <p>No storage backends are configured on this server. A deployment administrator must configure them first.</p>}
        <div className="client-storage-list">{keys.map(key => {
          const draft = drafts[key] || { access: 'none', prefixes: '' }
          const available = data.backends.includes(key)
          return <article key={key} className="submission-card client-storage-card">
            <div className="client-section-heading"><h2><Database size={18} aria-hidden="true" /> {key}</h2>
              <span className="client-badge">{available ? 'Configured' : 'Unavailable'}</span></div>
            {!available && <p role="alert">This backend is no longer configured here. Set it to No access before saving.</p>}
            <label>Access for {key}<select value={draft.access} onChange={event => update(key, { access: event.target.value as Draft['access'] })}>
              <option value="none">No access</option><option value="prefixes" disabled={!available}>Specific prefixes</option>
              <option value="all" disabled={!available}>Entire backend</option>
            </select></label>
            {draft.access === 'prefixes' && <label>Allowed prefixes for {key}<textarea rows={3} required maxLength={16416}
              value={draft.prefixes} onChange={event => update(key, { prefixes: event.target.value })} placeholder={'incoming/client-a/\narchive/client-a/'} />
              <small>One relative folder or object prefix per line, up to 32. No absolute paths or parent-directory traversal.</small></label>}
          </article>
        })}</div></>}
    <div className="client-form-footer"><Button type="submit">Review storage access</Button></div>
  </fieldset></form>
}

export default function ClientStorage({ session }: { session: Session }) {
  const route = useParams()
  const workspace = useContext(ClientWorkspace)
  const clientId = Number(workspace?.clientId || route.clientId)
  const [confirmation, setConfirmation] = useState<Change | null>(null)
  const [needsRefresh, setNeedsRefresh] = useState(false)
  const access = useQuery({ queryKey: ['client-storage', clientId], queryFn: ({ signal }) => request('/api/ui/v1/service-clients/{client_id}/storage', 'get', {
    params: { client_id: clientId }, signal }), retry: false, gcTime: 0, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })
  const save = useMutation({ retry: false, mutationFn: (body: Change) => request('/api/ui/v1/service-clients/{client_id}/storage', 'put', {
    params: { client_id: clientId }, csrf: session.csrf_token, body }),
    onSettled: () => { setConfirmation(null); setNeedsRefresh(true) } })
  useClientPanelGuard('storage', confirmation !== null || save.isPending)
  const busy = access.isFetching || save.isPending || confirmation !== null
  return <section className="page management-page client-page"><ClientNavigation clientId={clientId} />
    <div className="page-heading"><div><p className="eyebrow">INTEGRATIONS</p><h1>Storage access</h1><p className="muted">Service client #{clientId}</p></div>
      <Button variant="secondary" disabled={busy} onClick={async () => { save.reset(); const result = await access.refetch(); if (!result.error) setNeedsRefresh(false) }}>
        <RefreshCw size={14} aria-hidden="true" />Refresh storage access</Button></div>
    <p className="callout">Choose where this client may submit deferred files. Backend locations stay deployment-managed.
      Access is checked at submission and again before the intake worker starts copying. A copy already in progress may continue.</p>
    {access.isPending && <p role="status">Loading storage access…</p>}
    {access.error && <p role="alert" className="error">{access.error.message}</p>}
    {save.isSuccess && <p role="status" className="callout">Storage access saved. Refresh before editing again.</p>}
    {save.error && <p role="alert" className="error">{save.error.message} Refresh and reconcile before another save; requests are not automatically retried.</p>}
    {needsRefresh && <p>Refresh storage access to load the current policy.</p>}
    {!needsRefresh && !access.error && access.data && <>
      <div className="client-section-heading"><h2>Current access</h2><span className="client-badge">{access.data.mode === 'custom' ? 'Custom client access' : 'Deployment settings'}</span></div>
      <GrantSummary grants={access.data.grants} backends={access.data.backends} />
      {access.data.managed && <p>Managed compatibility storage access is read-only.</p>}
      <StorageForm key={access.dataUpdatedAt} data={access.data} disabled={busy} review={setConfirmation} />
      <p className="muted client-note">Configured here does not prove that an intake worker can reach the backend. Deployment settings can differ between processes.</p>
    </>}
    <Dialog open={confirmation !== null} locked={save.isPending} onOpenChange={open => { if (!open && !save.isPending) setConfirmation(null) }}
      title="Update storage access?" description={confirmation?.mode === 'environment'
        ? `Return client #${clientId} to deployment-managed access? The grants below will apply on this server.`
        : `Replace all storage grants for client #${clientId}? Pending deferred work will use the current access policy before copying.`}>
      <GrantSummary grants={confirmation?.mode === 'environment' ? access.data?.environment_grants || [] : confirmation?.grants || []} backends={access.data?.backends || []} />
      <div className="report-actions"><Button variant="secondary" disabled={save.isPending} onClick={() => setConfirmation(null)}>Cancel</Button>
        <Button disabled={save.isPending} onClick={() => { if (confirmation) save.mutate(confirmation) }}>{save.isPending ? 'Saving…' : 'Confirm storage access'}</Button></div>
    </Dialog>
  </section>
}
