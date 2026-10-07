import { ErrorMessage } from '../components/error-message'
import { useContext, useId, useState, type FormEvent } from 'react'
import { useParams, useSearchParams } from 'react-router-dom'
import { GitBranch, Plus, RefreshCw } from 'lucide-react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import type { components } from '../lib/api.generated'
import { formatBytes } from '../lib/storage'
import { Button } from '../components/ui/button'
import { Dialog } from '../components/ui/dialog'
import { ClientNavigation } from '../components/client-navigation'
import { ClientWorkspace, useClientPanelGuard } from '../components/client-workspace'
import { INCONCLUSIVE_HELP, RulesEditor, RulesTable, type EngineChoice, type RulesPolicy } from '../components/profile-rules'

type Profile = components['schemas']['ProfileSummary']
type Profiles = components['schemas']['ClientProfiles']
type Change = { kind: 'create'; name: string; engine_ids: number[]; inconclusive: RulesPolicy['inconclusive'] }
  | { kind: 'update'; profile_id: number; name: string; enabled: boolean; expected_revision: number }
  | { kind: 'default'; profile_id: number; expected_revision: number; expected_default_profile_id: number | null }
  | { kind: 'delete'; profile_id: number; expected_revision: number }
  | { kind: 'rules'; profile_id: number; expected_revision: number; rules: RulesPolicy }

const SAVED: Record<Change['kind'], string> = {
  rules: 'Rules saved.', create: 'Profile created.', update: 'Profile saved.', default: 'Default profile changed.', delete: 'Profile deleted.',
}

/** The only settings outside the rules: they act before any rule runs. */
function OutsideRules({ data }: { data: Profiles }) {
  const upload = data.upload_cap_bytes ? `files over ${formatBytes(data.upload_cap_bytes)} are refused` : 'no upload limit is set'
  return <p className="client-note muted">Before any rule: over the API {upload} (System limits &amp; notifications).
    {(data.gateways ?? []).map(gateway => <span key={gateway.port}> ICAP gateway on port {gateway.port}: {gateway.max_bytes == null ? 'size limit not reported'
      : gateway.max_bytes ? `files over ${formatBytes(gateway.max_bytes)} are ${gateway.fail_closed ? 'blocked' : 'allowed unscanned'}` : 'no size limit'};
      {' '}{gateway.wait_seconds == null ? 'wait time not reported' : `no verdict within ${gateway.wait_seconds} s`} or MASP unreachable: {gateway.fail_closed ? 'blocked' : 'allowed'}.</span>)}
  </p>
}

function ProfileCard({ profile, engines, disabled, review, edit, editRules, defaultId }: { profile: Profile; engines: EngineChoice[]; disabled: boolean; review: (value: Change) => void; edit: () => void; editRules: () => void; defaultId: number | null }) {
  return <article className="submission-card client-profile"><div className="client-section-heading"><div className="client-identity"><span className="client-icon"><GitBranch size={20} aria-hidden="true" /></span><div><h2>{profile.name}</h2>
    <p className="muted client-note">{profile.is_default ? 'Default profile: used when a request names no profile, and by the ICAP gateway' : 'Named profile'} · <code>profile_id={profile.id}</code></p></div></div>
    <span className={`client-badge ${profile.enabled ? 'client-badge-enabled' : ''}`}>{profile.enabled ? 'Enabled' : 'Disabled'}</span></div>
    <div className="report-actions"><Button variant="secondary" disabled={disabled || profile.incomplete} onClick={edit}>Rename or disable</Button>
      <Button variant="secondary" disabled={disabled || profile.incomplete || profile.is_default || !profile.enabled || !profile.engine_ids.length} onClick={() => review({ kind: 'default', profile_id: profile.id, expected_revision: profile.management_revision, expected_default_profile_id: defaultId })}>Make default</Button>
      <Button variant="destructive" disabled={disabled || profile.incomplete || profile.is_default} onClick={() => review({ kind: 'delete', profile_id: profile.id, expected_revision: profile.management_revision })}>Delete profile</Button></div>
    <section className="profile-policy" aria-label={`Rules for ${profile.name}`}><div className="client-section-heading"><h3>Rules</h3>
      <Button variant="secondary" disabled={disabled} onClick={editRules}>Edit rules</Button></div>
      {profile.rules ? <RulesTable rules={profile.rules} engines={engines} />
        : <p role="alert">This profile has no readable rules, so its files are not allowed automatically. Edit rules to set them.</p>}
    </section>
  </article>
}

function CreateForm({ engines, busy, onCancel, onReview }: { engines: EngineChoice[]; busy: boolean; onCancel: () => void; onReview: (change: Change) => void }) {
  const helpId = useId()
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    onReview({ kind: 'create', name: String(data.get('name') || ''), engine_ids: data.getAll('engine_ids').map(Number),
      inconclusive: data.get('inconclusive') as RulesPolicy['inconclusive'] })
  }
  return <form className="submission-card" onSubmit={submit}><fieldset disabled={busy}>
    <legend className="client-form-title">New scan profile</legend>
    <label>Profile name<input name="name" required maxLength={100} /></label>
    <p className="muted client-note">The profile starts with one rule that sends every file to these engines; add more rules afterwards. The current default profile stays in place.</p>
    <fieldset className="profile-rule-engines"><legend>Engines</legend>{engines.filter(engine => !engine.excluded_reason).map(engine =>
      <label key={engine.id} className="check-row"><input type="checkbox" name="engine_ids" value={engine.id} />{engine.display_name}</label>)}</fieldset>
    <div className="field-with-help"><label>When the result is not conclusive<select name="inconclusive" required defaultValue="" aria-describedby={helpId}>
      <option value="" disabled>Choose…</option><option value="block">Block</option><option value="allow">Allow, labelled Not fully scanned</option></select></label>
      <small id={helpId} className="field-help">{INCONCLUSIVE_HELP}</small></div>
    <div className="client-form-footer"><Button type="button" variant="secondary" onClick={onCancel}>Cancel</Button><Button type="submit">Review profile</Button></div>
  </fieldset></form>
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
  const [rulesEditor, setRulesEditor] = useState<Profile | null>(null)
  const profiles = useQuery({ queryKey: ['client-profiles', clientId, after], queryFn: ({ signal }) => request('/api/ui/v1/service-clients/{client_id}/profiles', 'get', {
    params: { client_id: clientId }, query: new URLSearchParams(after ? { after } : {}), signal }),
    retry: false, gcTime: 0, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })
  const save = useMutation({ retry: false, mutationFn: async (change: Change) => {
    const base = { csrf: session.csrf_token }
    if (change.kind === 'create') return request('/api/ui/v1/service-clients/{client_id}/profiles', 'post', {
      ...base, params: { client_id: clientId }, body: { name: change.name, engine_ids: change.engine_ids, inconclusive: change.inconclusive } })
    const params = { client_id: clientId, profile_id: change.profile_id }
    if (change.kind === 'update') return request('/api/ui/v1/service-clients/{client_id}/profiles/{profile_id}', 'put', {
      ...base, params, body: { name: change.name, enabled: change.enabled, expected_revision: change.expected_revision } })
    if (change.kind === 'rules') return request('/api/ui/v1/service-clients/{client_id}/profiles/{profile_id}/policy', 'put', {
      ...base, params, body: { expected_revision: change.expected_revision, rules: change.rules } })
    if (change.kind === 'default') return request('/api/ui/v1/service-clients/{client_id}/profiles/{profile_id}/default', 'put', {
      ...base, params, body: { expected_revision: change.expected_revision, expected_default_profile_id: change.expected_default_profile_id } })
    return request('/api/ui/v1/service-clients/{client_id}/profiles/{profile_id}', 'delete', { ...base, params, body: { expected_revision: change.expected_revision } })
  },
  // A saved change is followed by a fresh read so the next edit starts from current revisions.
  // A failed or uncertain write is never replayed: the operator refreshes and reconciles first.
  onSuccess: async () => { const result = await profiles.refetch(); if (result.error) setNeedsRefresh(true) },
  onError: () => setNeedsRefresh(true),
  onSettled: () => { setConfirmation(null); setEditor(null); setRulesEditor(null) } })
  const busy = profiles.isFetching || save.isPending || confirmation !== null
  useClientPanelGuard('profiles', save.isPending || confirmation !== null)
  function reviewRename(event: FormEvent<HTMLFormElement>, profile: Profile) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    setConfirmation({ kind: 'update', profile_id: profile.id, expected_revision: profile.management_revision,
      name: String(data.get('name') || ''), enabled: profile.is_default || data.get('enabled') === 'enabled' })
  }
  const engines = profiles.data?.engines ?? []
  const names = (ids: number[]) => ids.map(id => engines.find(engine => engine.id === id)?.display_name ?? `engine #${id}`).join(', ')
  const profileName = (id: number) => profiles.data?.items.find(item => item.id === id)?.name ?? `profile #${id}`
  function describe(change: Change) {
    if (change.kind === 'create') return `Create ${change.name}? Its one rule sends every file to ${change.engine_ids.length ? names(change.engine_ids) : 'no engine yet'}; `
      + `an inconclusive result is ${change.inconclusive === 'block' ? 'blocked' : 'allowed and labelled'}. The current default profile stays in place.`
    const name = profileName(change.profile_id)
    if (change.kind === 'rules') return `Replace the rules of ${name} with the ${change.rules.rules.length} below? They apply to files accepted from now on, including this client's ICAP gateway.`
    if (change.kind === 'delete') return `Delete ${name}? New requests can no longer choose it. Scans it accepted are kept, and its name stays reserved.`
    if (change.kind === 'default') return `Make ${name} the default? It is used when a request names no profile, and by this client's ICAP gateway. Accepted scans are not changed.`
    return `${name === change.name ? `Keep the name ${name}` : `Rename ${name} to ${change.name}`} and set it ${change.enabled ? 'enabled' : 'disabled'}? Accepted scans are not changed.`
  }
  const locked = busy || !!editor || !!rulesEditor || !profiles.data || profiles.data.managed || profiles.data.engines_incomplete
  return <section className="page management-page client-page"><ClientNavigation clientId={clientId} /><div className="page-heading"><div><p className="eyebrow">INTEGRATIONS</p><h1>Scan profiles</h1>
    <p className="muted">Each profile is a list of rules: which engines scan which files, and what is blocked or allowed.</p></div><div className="client-heading-actions"><Button variant="secondary" disabled={busy} onClick={async () => {
      save.reset(); setEditor(null); setRulesEditor(null); const result = await profiles.refetch(); if (!result.error) setNeedsRefresh(false)
    }}><RefreshCw size={14} aria-hidden="true" />Refresh</Button>
      <Button disabled={locked || needsRefresh || !!profiles.error} onClick={() => setEditor('create')}><Plus size={14} aria-hidden="true" />Add profile</Button></div></div>
    {profiles.isPending && <p role="status">Loading profiles…</p>}
    {profiles.error && <p role="alert" className="error"><ErrorMessage message={profiles.error.message || ''} /></p>}
    {save.isSuccess && !needsRefresh && save.variables && <p role="status" className="callout">{SAVED[save.variables.kind]}</p>}
    {save.error && <p role="alert" className="error"><ErrorMessage message={save.error.message || ''} /> Refresh and check before another save; requests are not automatically retried.</p>}
    {!needsRefresh && !profiles.error && profiles.data && <>
      {profiles.data.managed ? <p>Managed compatibility routing is read-only: it follows the deployment's engines and ICAP gateway settings.</p>
        : <OutsideRules data={profiles.data} />}
      {profiles.data.engines_incomplete && <p role="alert">More than 100 engine instances exist, beyond what this editor can show; this incomplete list cannot be saved.</p>}
      {editor === 'create' && <CreateForm engines={engines} busy={busy} onCancel={() => setEditor(null)} onReview={setConfirmation} />}
      {!profiles.data.items.length && <p>No profiles on this page.</p>}
      {profiles.data.items.map(profile => rulesEditor?.id === profile.id
        ? <RulesEditor key={`rules-${profile.id}`} name={profile.name} rules={profile.rules ?? null} engines={engines} disabled={busy}
            onCancel={() => setRulesEditor(null)}
            onReview={rules => setConfirmation({ kind: 'rules', profile_id: profile.id, expected_revision: profile.management_revision, rules })} />
        : editor !== 'create' && editor?.id === profile.id
        ? <form key={`edit-${profile.id}`} className="submission-card" onSubmit={event => reviewRename(event, profile)}><fieldset disabled={busy}>
            <legend className="client-form-title">Edit {profile.name}</legend>
            <label>Profile name<input name="name" required maxLength={100} defaultValue={profile.name} /></label>
            <label>Profile state<select name="enabled" disabled={profile.is_default} defaultValue={profile.enabled ? 'enabled' : 'disabled'}><option value="enabled">Enabled</option><option value="disabled">Disabled</option></select></label>
            {profile.is_default && <p className="muted client-note">The default profile cannot be disabled.</p>}
            <div className="client-form-footer"><Button type="button" variant="secondary" onClick={() => setEditor(null)}>Cancel</Button><Button type="submit">Review profile</Button></div>
          </fieldset></form>
        : <ProfileCard key={`${profile.id}-${profiles.dataUpdatedAt}`} profile={profile} engines={engines}
            disabled={locked} review={setConfirmation} edit={() => setEditor(profile)}
            editRules={() => setRulesEditor(profile)} defaultId={profiles.data!.default_profile_id} />)}
      {Boolean(after || profiles.data.next_after) && <div className="history-pagination"><Button variant="secondary" disabled={busy || !after} onClick={() => setAfter('')}>First profiles</Button>
        <Button variant="secondary" disabled={busy || !profiles.data.next_after} onClick={() => setAfter(String(profiles.data!.next_after))}>Next profiles</Button></div>}
    </>}
    {needsRefresh && <p>Refresh to load the current profiles before editing again.</p>}
    <Dialog open={confirmation !== null} onOpenChange={open => { if (!open && !save.isPending) setConfirmation(null) }} locked={save.isPending}
      title={confirmation?.kind === 'rules' ? 'Save rules?' : 'Confirm profile change'} description={confirmation ? describe(confirmation) : ''}>
      {confirmation?.kind === 'rules' && <RulesTable rules={confirmation.rules} engines={engines} />}
      <div className="report-actions"><Button variant="secondary" disabled={save.isPending} onClick={() => setConfirmation(null)}>Cancel</Button>
        <Button disabled={save.isPending || (confirmation?.kind === 'create' && (!confirmation.engine_ids.length || !confirmation.inconclusive))} onClick={() => { if (confirmation) save.mutate(confirmation) }}>{save.isPending ? 'Saving…' : confirmation?.kind === 'rules' ? 'Save rules' : 'Confirm profile change'}</Button></div>
    </Dialog>
  </section>
}
