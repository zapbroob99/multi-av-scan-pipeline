import { useContext, useState, type FormEvent } from 'react'
import { useParams, useSearchParams } from 'react-router-dom'
import { Cpu, GitBranch, Plus, RefreshCw } from 'lucide-react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import type { components } from '../lib/api.generated'
import { Button } from '../components/ui/button'
import { Dialog } from '../components/ui/dialog'
import { ClientNavigation } from '../components/client-navigation'
import { ClientWorkspace, useClientPanelGuard } from '../components/client-workspace'

type Profile = components['schemas']['ProfileSummary']
type Choice = components['schemas']['ProfileEngineChoice']
type Change = { kind: 'engines'; profile_id: number; engine_ids: number[]; expected_engine_ids: number[]; expected_revision: number }
  | { kind: 'create'; name: string; engine_ids: number[] }
  | { kind: 'update'; profile_id: number; name: string; enabled: boolean; expected_revision: number }
  | { kind: 'default'; profile_id: number; expected_revision: number; expected_default_profile_id: number | null }
  | { kind: 'delete'; profile_id: number; expected_revision: number }

function ProfileCard({ profile, engines, disabled, review, edit, defaultId }: { profile: Profile; engines: Choice[]; disabled: boolean; review: (value: Change) => void; edit: () => void; defaultId: number | null }) {
  const [selected, setSelected] = useState(profile.engine_ids)
  const missing = profile.engine_ids.some(id => !engines.some(engine => engine.id === id))
  return <article className="submission-card client-profile"><div className="client-section-heading"><div className="client-identity"><span className="client-icon"><GitBranch size={20} aria-hidden="true" /></span><div><h2>{profile.name}</h2>
    <p className="muted client-note">Profile #{profile.id} · {profile.is_default ? 'Default profile' : 'Named profile'}</p></div></div>
    <span className={`client-badge ${profile.enabled ? 'client-badge-enabled' : ''}`}>{profile.enabled ? 'Enabled' : 'Disabled'}</span></div>
    <div className="report-actions"><Button variant="secondary" disabled={disabled || profile.incomplete} onClick={edit}>Edit profile</Button>
      <Button variant="secondary" disabled={disabled || profile.incomplete || profile.is_default || !profile.enabled || !profile.engine_ids.length} onClick={() => review({ kind: 'default', profile_id: profile.id, expected_revision: profile.management_revision, expected_default_profile_id: defaultId })}>Make default</Button>
      <Button variant="destructive" disabled={disabled || profile.incomplete || profile.is_default} onClick={() => review({ kind: 'delete', profile_id: profile.id, expected_revision: profile.management_revision })}>Delete profile</Button></div>
    <p className="muted client-note">API selection: <code>profile_id={profile.id}</code>{profile.is_default ? ' · Used when a request omits profile_id.' : ''}</p>
    {(profile.incomplete || missing) && <p role="alert">Routing metadata is incomplete. Refresh to try again; saving is disabled so a partial list is never saved.</p>}
    <fieldset disabled={disabled || profile.incomplete || missing}><legend>Assigned engine instances</legend>
      <p className="muted client-note">Select the engines required by this profile. Review your selection before saving.</p>
      <div className="client-engine-options">{engines.map(engine => <label className="client-engine-option" key={engine.id}><input type="checkbox" checked={selected.includes(engine.id)}
        onChange={event => setSelected(current => event.target.checked ? [...current, engine.id] : current.filter(id => id !== engine.id))} />
        <Cpu size={18} aria-hidden="true" /><span><strong>{engine.display_name}</strong><small>#{engine.id} · {engine.adapter_key}{engine.enabled ? '' : ' · disabled'}</small></span></label>)}</div>
      <div className="client-form-footer"><span className="muted">{selected.length} selected</span><Button disabled={!selected.length} onClick={() => review({ kind: 'engines', profile_id: profile.id, engine_ids: selected, expected_engine_ids: profile.engine_ids, expected_revision: profile.management_revision })}>Review engine routing</Button></div>
    </fieldset></article>
}

export default function ClientProfiles({ session }: { session: Session }) {
  const routeClientId = useParams().clientId
  const workspace = useContext(ClientWorkspace)
  const clientId = workspace?.clientId ?? Number(routeClientId)
  const [params, setParams] = useSearchParams()
  const [dialogAfter, setDialogAfter] = useState('')
  const after = workspace ? dialogAfter : params.get('after') || ''
  const setAfter = (value: string) => workspace ? setDialogAfter(value) : setParams(value ? { after: value } : {})
  const [confirmation, setConfirmation] = useState<Change | null>(null)
  const [needsRefresh, setNeedsRefresh] = useState(false)
  const [editor, setEditor] = useState<Profile | 'create' | null>(null)
  const profiles = useQuery({ queryKey: ['client-profiles', clientId, after], queryFn: ({ signal }) => request('/api/ui/v1/service-clients/{client_id}/profiles', 'get', {
    params: { client_id: clientId }, query: new URLSearchParams(after ? { after } : {}), signal }),
    retry: false, gcTime: 0, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })
  const save = useMutation({ retry: false, mutationFn: async (change: Change) => {
    const base = { csrf: session.csrf_token }
    if (change.kind === 'create') return request('/api/ui/v1/service-clients/{client_id}/profiles', 'post', {
      ...base, params: { client_id: clientId }, body: { name: change.name, engine_ids: change.engine_ids } })
    const params = { client_id: clientId, profile_id: change.profile_id }
    if (change.kind === 'engines') return request('/api/ui/v1/service-clients/{client_id}/profiles/{profile_id}/engines', 'put', {
      ...base, params, body: { engine_ids: change.engine_ids, expected_engine_ids: change.expected_engine_ids, expected_revision: change.expected_revision } })
    if (change.kind === 'update') return request('/api/ui/v1/service-clients/{client_id}/profiles/{profile_id}', 'put', {
      ...base, params, body: { name: change.name, enabled: change.enabled, expected_revision: change.expected_revision } })
    if (change.kind === 'default') return request('/api/ui/v1/service-clients/{client_id}/profiles/{profile_id}/default', 'put', {
      ...base, params, body: { expected_revision: change.expected_revision, expected_default_profile_id: change.expected_default_profile_id } })
    return request('/api/ui/v1/service-clients/{client_id}/profiles/{profile_id}', 'delete', { ...base, params, body: { expected_revision: change.expected_revision } })
  }, onSettled: () => { setConfirmation(null); setEditor(null); setNeedsRefresh(true) } })
  const busy = profiles.isFetching || save.isPending || confirmation !== null
  useClientPanelGuard('profiles', save.isPending || confirmation !== null)
  function reviewForm(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const name = String(data.get('name') || '')
    if (editor === 'create') setConfirmation({ kind: 'create', name, engine_ids: data.getAll('engine_ids').map(Number) })
    else if (editor) setConfirmation({ kind: 'update', profile_id: editor.id, expected_revision: editor.management_revision, name,
      enabled: editor.is_default || data.get('enabled') === 'enabled' })
  }
  const description = !confirmation ? '' : confirmation.kind === 'create' ? `Create ${confirmation.name} for client #${clientId} with required engine IDs ${confirmation.engine_ids.join(', ')}?`
    : confirmation.kind === 'engines' ? `For client #${clientId}, replace profile #${confirmation.profile_id} routing with engine instances ${confirmation.engine_ids.join(', ')}. Existing scan snapshots are preserved. A changed prior selection will be rejected.`
    : confirmation.kind === 'delete' ? `Delete profile #${confirmation.profile_id}? New submissions cannot select it. Existing scans and deferred work are preserved; its name remains reserved.`
    : confirmation.kind === 'default' ? `Use profile #${confirmation.profile_id} for new requests that omit profile_id, including this client's ICAP gateway? Existing scans are preserved.`
    : `Rename profile #${confirmation.profile_id} to ${confirmation.name} and set it ${confirmation.enabled ? 'enabled' : 'disabled'}? Existing scans are preserved.`
  return <section className="page management-page client-page"><ClientNavigation clientId={clientId} /><div className="page-heading"><div><p className="eyebrow">INTEGRATIONS</p><h1>Client profile routing</h1>
    <p className="muted">Service client #{clientId}</p></div><div className="client-heading-actions"><Button variant="secondary" disabled={busy} onClick={async () => {
      save.reset(); setEditor(null); const result = await profiles.refetch(); if (!result.error) setNeedsRefresh(false)
    }}><RefreshCw size={14} aria-hidden="true" />Refresh profiles</Button>
      <Button disabled={busy || needsRefresh || !!editor || !profiles.data || !!profiles.error || profiles.data.managed || profiles.data.engines_incomplete} onClick={() => setEditor('create')}><Plus size={14} aria-hidden="true" />Add profile</Button></div></div>
    <p className="callout">Changes apply to future submissions. Selected engines are required; accepted scans keep their original routing.
      Disabled engines and metered reputation services remain excluded from API/ICAP scans. Engine selection alone does not prove scan coverage.</p>
    {profiles.isPending && <p role="status">Loading profiles…</p>}
    {profiles.error && <p role="alert" className="error">{profiles.error.message}</p>}
    {save.isSuccess && <p role="status" className="callout">{save.variables?.kind === 'engines' ? 'Profile routing saved. Refresh before editing again.' : 'Profile change saved. Refresh before editing again.'}</p>}
    {save.error && <p role="alert" className="error">{save.error.message} Refresh and reconcile before another save; requests are not automatically retried.</p>}
    {!needsRefresh && !profiles.error && profiles.data && <>
      {profiles.data.managed && <p>Managed compatibility routing is read-only.</p>}
      {profiles.data.engines_incomplete && <p role="alert">More than 100 engine instances exist, beyond what this editor can show; this incomplete list cannot be saved.</p>}
      {editor && <form key={editor === 'create' ? 'create' : editor.id} className="submission-card" onSubmit={reviewForm}><fieldset disabled={busy}>
        <legend className="client-form-title">{editor === 'create' ? 'New scan profile' : `Edit ${editor.name}`}</legend>
        <label>Profile name<input name="name" required maxLength={100} defaultValue={editor === 'create' ? '' : editor.name} /></label>
        {editor !== 'create' && <label>Profile state<select name="enabled" disabled={editor.is_default} defaultValue={editor.enabled ? 'enabled' : 'disabled'}><option value="enabled">Enabled</option><option value="disabled">Disabled</option></select></label>}
        {editor === 'create' && <><p className="muted client-note">Choose at least one required engine. This creates a named profile; your current default stays in place.</p>
          <div className="client-engine-options">{profiles.data.engines.map(engine => <label key={engine.id} className="client-engine-option"><input type="checkbox" name="engine_ids" value={engine.id} /><span>{engine.display_name}<small>#{engine.id}{engine.enabled ? '' : ' · disabled'}</small></span></label>)}</div></>}
        <div className="client-form-footer"><Button type="button" variant="secondary" onClick={() => setEditor(null)}>Cancel editing</Button><Button type="submit">Review profile</Button></div>
      </fieldset></form>}
      {!profiles.data.items.length && <p>No profiles on this page.</p>}
      {profiles.data.items.map(profile => <ProfileCard key={`${profile.id}-${profiles.dataUpdatedAt}`} profile={profile} engines={profiles.data!.engines}
        disabled={busy || !!editor || profiles.data!.managed || profiles.data!.engines_incomplete} review={setConfirmation} edit={() => setEditor(profile)} defaultId={profiles.data!.default_profile_id} />)}
      <div className="history-pagination"><Button variant="secondary" disabled={busy || !after} onClick={() => setAfter('')}>First profiles</Button>
        <Button variant="secondary" disabled={busy || !profiles.data.next_after} onClick={() => setAfter(String(profiles.data!.next_after))}>Next profiles</Button></div>
    </>}
    {needsRefresh && <p>Refresh profiles to load current routing.</p>}
    <Dialog open={confirmation !== null} onOpenChange={open => { if (!open && !save.isPending) setConfirmation(null) }} locked={save.isPending} title={confirmation?.kind === 'engines' ? 'Save profile routing?' : 'Confirm profile change'} description={description}>
      <div className="report-actions"><Button variant="secondary" disabled={save.isPending} onClick={() => setConfirmation(null)}>Cancel</Button>
        <Button disabled={save.isPending || (confirmation?.kind === 'create' && !confirmation.engine_ids.length)} onClick={() => { if (confirmation) save.mutate(confirmation) }}>{save.isPending ? 'Saving…' : confirmation?.kind === 'engines' ? 'Confirm engine routing' : 'Confirm profile change'}</Button></div>
    </Dialog>
  </section>
}
