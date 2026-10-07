import { ErrorMessage } from '../components/error-message'
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
import { PolicySummary, ProfilePolicyEditor, policySummary, type ProfilePolicy } from '../components/profile-policy'

type Profile = components['schemas']['ProfileSummary']
type Outcome = components['schemas']['ProfileOutcome']
type Choice = components['schemas']['ProfileEngineChoice']
type Change = { kind: 'engines'; profile_id: number; engine_ids: number[]; expected_engine_ids: number[]; expected_revision: number }
  | { kind: 'create'; name: string; engine_ids: number[] }
  | { kind: 'update'; profile_id: number; name: string; enabled: boolean; expected_revision: number }
  | { kind: 'default'; profile_id: number; expected_revision: number; expected_default_profile_id: number | null }
  | { kind: 'delete'; profile_id: number; expected_revision: number }
  | { kind: 'policy'; profile_id: number; expected_revision: number; policy: ProfilePolicy }

const SAVED: Record<Change['kind'], string> = {
  engines: 'Engines saved.', policy: 'File rules saved.', create: 'Profile created.',
  update: 'Profile saved.', default: 'Default profile changed.', delete: 'Profile deleted.',
}

/** What happens to this profile's files over the API and over ICAP, as the server computed it. */
function ProfileOutcomeTable({ name, outcome }: { name: string; outcome: Outcome }) {
  const running = outcome.engines.filter(engine => engine.runs)
  const left = outcome.engines.filter(engine => !engine.runs)
  const icapHeading = outcome.icap === 'gateway' ? `ICAP gateway (port ${outcome.icap_ports.join(', ')})` : 'ICAP gateway'
  return <section className="profile-outcome" aria-label={`What happens to files under ${name}`}>
    <h3>What happens to files</h3>
    <p className={running.length ? 'client-note' : 'client-note outcome-unknown'}>{running.length
      ? <>Scanned by {running.map(engine => engine.display_name).join(', ')}.</>
      : <>No assigned engine can scan API or ICAP files.</>}</p>
    {left.length > 0 && <ul className="outcome-left-out">{left.map(engine => <li key={engine.id}><strong>{engine.display_name}</strong> is left out: {engine.reason}</li>)}</ul>}
    {outcome.icap === 'not_default' && <p className="muted client-note">ICAP gateways use the default profile, so only the API column applies here.</p>}
    {outcome.icap === 'no_gateway' && <p className="muted client-note">No ICAP gateway reports for this client, so ICAP answers that depend on the gateway are unknown.</p>}
    <div className="history-table-wrap"><table className="outcome-table">
      <thead><tr><th scope="col">When</th><th scope="col">API</th>{outcome.icap !== 'not_default' && <th scope="col">{icapHeading}</th>}</tr></thead>
      <tbody>{outcome.lines.map(line => <tr key={line.topic}>
        <th scope="row">{line.label}</th>
        <td data-label="API">{line.api}</td>
        {outcome.icap !== 'not_default' && <td data-label="ICAP" className={line.icap_known ? undefined : 'outcome-unknown'}>{line.icap}</td>}
      </tr>)}</tbody></table></div>
  </section>
}

function ProfileCard({ profile, engines, disabled, review, edit, editPolicy, defaultId }: { profile: Profile; engines: Choice[]; disabled: boolean; review: (value: Change) => void; edit: () => void; editPolicy: () => void; defaultId: number | null }) {
  const [selected, setSelected] = useState(profile.engine_ids)
  const missing = profile.engine_ids.some(id => !engines.some(engine => engine.id === id))
  const changed = selected.length !== profile.engine_ids.length || selected.some(id => !profile.engine_ids.includes(id))
  return <article className="submission-card client-profile"><div className="client-section-heading"><div className="client-identity"><span className="client-icon"><GitBranch size={20} aria-hidden="true" /></span><div><h2>{profile.name}</h2>
    <p className="muted client-note">{profile.is_default ? 'Default profile: used when a request names no profile, and by the ICAP gateway' : 'Named profile'} · <code>profile_id={profile.id}</code></p></div></div>
    <span className={`client-badge ${profile.enabled ? 'client-badge-enabled' : ''}`}>{profile.enabled ? 'Enabled' : 'Disabled'}</span></div>
    <div className="report-actions"><Button variant="secondary" disabled={disabled || profile.incomplete} onClick={edit}>Rename or disable</Button>
      <Button variant="secondary" disabled={disabled || profile.incomplete || profile.is_default || !profile.enabled || !profile.engine_ids.length} onClick={() => review({ kind: 'default', profile_id: profile.id, expected_revision: profile.management_revision, expected_default_profile_id: defaultId })}>Make default</Button>
      <Button variant="destructive" disabled={disabled || profile.incomplete || profile.is_default} onClick={() => review({ kind: 'delete', profile_id: profile.id, expected_revision: profile.management_revision })}>Delete profile</Button></div>
    <section className="profile-policy" aria-label={`File rules for ${profile.name}`}><div className="client-section-heading"><h3>File rules</h3>
      <Button variant="secondary" disabled={disabled} onClick={editPolicy}>Edit rules</Button></div>
      <PolicySummary policy={profile.policy} invalid={profile.policy_invalid} /></section>
    {profile.outcome && <ProfileOutcomeTable name={profile.name} outcome={profile.outcome} />}
    {(profile.incomplete || missing) && <p role="alert">Routing metadata is incomplete. Refresh to try again; saving is disabled so a partial list is never saved.</p>}
    <fieldset disabled={disabled || profile.incomplete || missing}><legend>Engines</legend>
      <p className="muted client-note">Every selected engine scans each file this profile accepts.</p>
      <div className="client-engine-options">{engines.map(engine => <label className="client-engine-option" key={engine.id}><input type="checkbox" checked={selected.includes(engine.id)}
        onChange={event => setSelected(current => event.target.checked ? [...current, engine.id] : current.filter(id => id !== engine.id))} />
        <Cpu size={18} aria-hidden="true" /><span><strong>{engine.display_name}</strong><small>{engine.adapter_key}{engine.excluded_reason ? ` · not used for API or ICAP files: ${engine.excluded_reason}` : ''}</small></span></label>)}</div>
      <div className="client-form-footer"><span className="muted">{selected.length} selected{changed ? ' · not saved' : ''}</span><Button disabled={!selected.length || !changed} onClick={() => review({ kind: 'engines', profile_id: profile.id, engine_ids: selected, expected_engine_ids: profile.engine_ids, expected_revision: profile.management_revision })}>Review engine changes</Button></div>
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
  const [policyEditor, setPolicyEditor] = useState<Profile | null>(null)
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
    if (change.kind === 'policy') return request('/api/ui/v1/service-clients/{client_id}/profiles/{profile_id}/policy', 'put', {
      ...base, params, body: { expected_revision: change.expected_revision, policy: change.policy } })
    if (change.kind === 'default') return request('/api/ui/v1/service-clients/{client_id}/profiles/{profile_id}/default', 'put', {
      ...base, params, body: { expected_revision: change.expected_revision, expected_default_profile_id: change.expected_default_profile_id } })
    return request('/api/ui/v1/service-clients/{client_id}/profiles/{profile_id}', 'delete', { ...base, params, body: { expected_revision: change.expected_revision } })
  },
  // A saved change is followed by a fresh read so the next edit starts from current revisions.
  // A failed or uncertain write is never replayed: the operator refreshes and reconciles first.
  onSuccess: async () => { const result = await profiles.refetch(); if (result.error) setNeedsRefresh(true) },
  onError: () => setNeedsRefresh(true),
  onSettled: () => { setConfirmation(null); setEditor(null); setPolicyEditor(null) } })
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
  const engineName = (id: number) => profiles.data?.engines.find(engine => engine.id === id)?.display_name ?? `engine #${id}`
  const names = (ids: number[]) => ids.map(engineName).join(', ')
  const profileName = (id: number) => profiles.data?.items.find(item => item.id === id)?.name ?? `profile #${id}`
  function describe(change: Change) {
    if (change.kind === 'create') return `Create profile ${change.name} with ${change.engine_ids.length ? names(change.engine_ids) : 'no engines yet'}? The current default profile stays in place.`
    const name = profileName(change.profile_id)
    if (change.kind === 'engines') {
      const added = change.engine_ids.filter(id => !change.expected_engine_ids.includes(id))
      const removed = change.expected_engine_ids.filter(id => !change.engine_ids.includes(id))
      return [`Engines for ${name}.`, added.length ? `Adds: ${names(added)}.` : '', removed.length ? `Removes: ${names(removed)}.` : '',
        'Applies to new files; files already accepted keep their engines.'].filter(Boolean).join(' ')
    }
    if (change.kind === 'delete') return `Delete ${name}? New requests can no longer choose it. Scans it accepted are kept, and its name stays reserved.`
    if (change.kind === 'policy') return `File rules for ${name}: ${policySummary(change.policy).join(' ') || "no rules of its own, so the server's limits and review handling apply."} Applies to new files, including this client's ICAP gateway.`
    if (change.kind === 'default') return `Make ${name} the default? It is used when a request names no profile, and by this client's ICAP gateway. Accepted scans are not changed.`
    return `${name === change.name ? `Keep the name ${name}` : `Rename ${name} to ${change.name}`} and set it ${change.enabled ? 'enabled' : 'disabled'}? Accepted scans are not changed.`
  }
  const locked = busy || !!editor || !!policyEditor || !profiles.data || profiles.data.managed || profiles.data.engines_incomplete
  return <section className="page management-page client-page"><ClientNavigation clientId={clientId} /><div className="page-heading"><div><p className="eyebrow">INTEGRATIONS</p><h1>Scan profiles</h1>
    <p className="muted">Which engines scan this client's files, and which file rules apply.</p></div><div className="client-heading-actions"><Button variant="secondary" disabled={busy} onClick={async () => {
      save.reset(); setEditor(null); setPolicyEditor(null); const result = await profiles.refetch(); if (!result.error) setNeedsRefresh(false)
    }}><RefreshCw size={14} aria-hidden="true" />Refresh</Button>
      <Button disabled={busy || needsRefresh || !!editor || !!policyEditor || !profiles.data || !!profiles.error || profiles.data.managed || profiles.data.engines_incomplete} onClick={() => setEditor('create')}><Plus size={14} aria-hidden="true" />Add profile</Button></div></div>
    <p className="callout">Changes apply to new files. Files already accepted keep the engines and rules they were accepted under.
      Disabled engines and paid reputation services never run for API or ICAP files; the Connection tab shows why an engine is left out.</p>
    {profiles.isPending && <p role="status">Loading profiles…</p>}
    {profiles.error && <p role="alert" className="error"><ErrorMessage message={profiles.error.message || ''} /></p>}
    {save.isSuccess && !needsRefresh && save.variables && <p role="status" className="callout">{SAVED[save.variables.kind]}</p>}
    {save.error && <p role="alert" className="error"><ErrorMessage message={save.error.message || ''} /> Refresh and check before another save; requests are not automatically retried.</p>}
    {!needsRefresh && !profiles.error && profiles.data && <>
      {profiles.data.managed && <p>Managed compatibility routing is read-only.</p>}
      {profiles.data.engines_incomplete && <p role="alert">More than 100 engine instances exist, beyond what this editor can show; this incomplete list cannot be saved.</p>}
      {editor === 'create' && <form className="submission-card" onSubmit={reviewForm}><fieldset disabled={busy}>
        <legend className="client-form-title">New scan profile</legend>
        <label>Profile name<input name="name" required maxLength={100} /></label>
        <p className="muted client-note">Choose at least one engine. The current default profile stays in place.</p>
        <div className="client-engine-options">{profiles.data.engines.map(engine => <label key={engine.id} className="client-engine-option"><input type="checkbox" name="engine_ids" value={engine.id} /><span>{engine.display_name}<small>{engine.adapter_key}{engine.enabled ? '' : ' · disabled'}</small></span></label>)}</div>
        <div className="client-form-footer"><Button type="button" variant="secondary" onClick={() => setEditor(null)}>Cancel</Button><Button type="submit">Review profile</Button></div>
      </fieldset></form>}
      {!profiles.data.items.length && <p>No profiles on this page.</p>}
      {profiles.data.items.map(profile => policyEditor?.id === profile.id
        ? <ProfilePolicyEditor key={`policy-${profile.id}`} name={profile.name} policy={profile.policy} invalid={profile.policy_invalid}
            disabled={busy} onCancel={() => setPolicyEditor(null)}
            onReview={policy => setConfirmation({ kind: 'policy', profile_id: profile.id, expected_revision: profile.management_revision, policy })} />
        : editor !== 'create' && editor?.id === profile.id
        ? <form key={`edit-${profile.id}`} className="submission-card" onSubmit={reviewForm}><fieldset disabled={busy}>
            <legend className="client-form-title">Edit {profile.name}</legend>
            <label>Profile name<input name="name" required maxLength={100} defaultValue={profile.name} /></label>
            <label>Profile state<select name="enabled" disabled={profile.is_default} defaultValue={profile.enabled ? 'enabled' : 'disabled'}><option value="enabled">Enabled</option><option value="disabled">Disabled</option></select></label>
            {profile.is_default && <p className="muted client-note">The default profile cannot be disabled.</p>}
            <div className="client-form-footer"><Button type="button" variant="secondary" onClick={() => setEditor(null)}>Cancel</Button><Button type="submit">Review profile</Button></div>
          </fieldset></form>
        : <ProfileCard key={`${profile.id}-${profiles.dataUpdatedAt}`} profile={profile} engines={profiles.data!.engines}
            disabled={locked} review={setConfirmation} edit={() => setEditor(profile)}
            editPolicy={() => setPolicyEditor(profile)} defaultId={profiles.data!.default_profile_id} />)}
      {Boolean(after || profiles.data.next_after) && <div className="history-pagination"><Button variant="secondary" disabled={busy || !after} onClick={() => setAfter('')}>First profiles</Button>
        <Button variant="secondary" disabled={busy || !profiles.data.next_after} onClick={() => setAfter(String(profiles.data!.next_after))}>Next profiles</Button></div>}
    </>}
    {needsRefresh && <p>Refresh to load the current profiles before editing again.</p>}
    <Dialog open={confirmation !== null} onOpenChange={open => { if (!open && !save.isPending) setConfirmation(null) }} locked={save.isPending}
      title={confirmation?.kind === 'engines' ? 'Save engine changes?' : confirmation?.kind === 'policy' ? 'Save file rules?' : 'Confirm profile change'} description={confirmation ? describe(confirmation) : ''}>
      <div className="report-actions"><Button variant="secondary" disabled={save.isPending} onClick={() => setConfirmation(null)}>Cancel</Button>
        <Button disabled={save.isPending || (confirmation?.kind === 'create' && !confirmation.engine_ids.length)} onClick={() => { if (confirmation) save.mutate(confirmation) }}>{save.isPending ? 'Saving…' : confirmation?.kind === 'engines' ? 'Save engines' : confirmation?.kind === 'policy' ? 'Save file rules' : 'Confirm profile change'}</Button></div>
    </Dialog>
  </section>
}
