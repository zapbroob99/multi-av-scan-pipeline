import { useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import type { components } from '../lib/api.generated'
import { Button } from '../components/ui/button'
import { Dialog } from '../components/ui/dialog'

type Profile = components['schemas']['ProfileSummary']
type Choice = components['schemas']['ProfileEngineChoice']
type Change = { profile_id: number; engine_ids: number[]; expected_engine_ids: number[] }

function ProfileCard({ profile, engines, disabled, review }: { profile: Profile; engines: Choice[]; disabled: boolean; review: (value: Change) => void }) {
  const [selected, setSelected] = useState(profile.engine_ids)
  const missing = profile.engine_ids.some(id => !engines.some(engine => engine.id === id))
  return <article className="submission-card report-engine"><h2>{profile.name}</h2>
    <p className="muted">Profile #{profile.id} · {profile.is_default ? 'Default profile' : 'Named profile'} · {profile.enabled ? 'Enabled' : 'Disabled'}</p>
    {(profile.incomplete || missing) && <p role="alert">Routing metadata is incomplete. Refresh or use legacy administration; saving is disabled.</p>}
    <fieldset disabled={disabled || profile.incomplete || missing}><legend>Assigned engine instances</legend>
      {engines.map(engine => <label className="report-engine" key={engine.id}><input type="checkbox" checked={selected.includes(engine.id)}
        onChange={event => setSelected(current => event.target.checked ? [...current, engine.id] : current.filter(id => id !== engine.id))} />
        {' '}{engine.display_name} · #{engine.id} · {engine.adapter_key}{engine.enabled ? '' : ' · disabled'}</label>)}
      <Button disabled={!selected.length} onClick={() => review({ profile_id: profile.id, engine_ids: selected, expected_engine_ids: profile.engine_ids })}>Review engine routing</Button>
    </fieldset></article>
}

export default function ClientProfiles({ session }: { session: Session }) {
  const clientId = Number(useParams().clientId)
  const [params, setParams] = useSearchParams()
  const after = params.get('after') || ''
  const [confirmation, setConfirmation] = useState<Change | null>(null)
  const [needsRefresh, setNeedsRefresh] = useState(false)
  const profiles = useQuery({ queryKey: ['client-profiles', clientId, after], queryFn: ({ signal }) => request('/api/ui/v1/service-clients/{client_id}/profiles', 'get', {
    params: { client_id: clientId }, query: new URLSearchParams(after ? { after } : {}), signal }),
    retry: false, gcTime: 0, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })
  const save = useMutation({ retry: false, mutationFn: (change: Change) => request('/api/ui/v1/service-clients/{client_id}/profiles/{profile_id}/engines', 'put', {
    params: { client_id: clientId, profile_id: change.profile_id }, csrf: session.csrf_token,
    body: { engine_ids: change.engine_ids, expected_engine_ids: change.expected_engine_ids } }),
    onSettled: () => { setConfirmation(null); setNeedsRefresh(true) } })
  const busy = profiles.isFetching || save.isPending || confirmation !== null
  return <section className="page management-page"><div className="page-heading"><div><p className="eyebrow">INTEGRATIONS</p><h1>Client profile routing</h1>
    <p className="muted">Service client #{clientId}</p></div><Button variant="secondary" disabled={busy} onClick={async () => {
      save.reset(); const result = await profiles.refetch(); if (!result.error) setNeedsRefresh(false)
    }}>Refresh profiles</Button></div>
    <nav className="report-actions"><Link to="/service-clients">Service clients</Link><Link to={`/service-clients/${clientId}/credentials`}>Credentials</Link></nav>
    <p className="callout">Changes affect future routing; accepted scan snapshots remain unchanged. Saving marks selected engines as required, matching the existing routing editor.
      Disabled engines and source-ineligible adapters remain excluded at intake. Selecting an external-quota engine does not bypass API/ICAP exclusions or prove coverage.</p>
    {profiles.isPending && <p role="status">Loading profiles…</p>}
    {profiles.error && <p role="alert" className="error">{profiles.error.message}</p>}
    {save.isSuccess && <p role="status" className="callout">Profile routing saved. Refresh before editing again.</p>}
    {save.error && <p role="alert" className="error">{save.error.message} Refresh and reconcile before another save; requests are not automatically retried.</p>}
    {!needsRefresh && !profiles.error && profiles.data && <>
      {profiles.data.managed && <p>Managed compatibility routing is read-only.</p>}
      {profiles.data.engines_incomplete && <p role="alert">More than 100 engine instances exist. Use legacy administration; this incomplete list cannot be saved.</p>}
      {!profiles.data.items.length && <p>No profiles on this page.</p>}
      {profiles.data.items.map(profile => <ProfileCard key={`${profile.id}-${profiles.dataUpdatedAt}`} profile={profile} engines={profiles.data!.engines}
        disabled={busy || profiles.data!.managed || profiles.data!.engines_incomplete} review={setConfirmation} />)}
      <div className="history-pagination"><Button variant="secondary" disabled={busy || !after} onClick={() => setParams({})}>First profiles</Button>
        <Button variant="secondary" disabled={busy || !profiles.data.next_after} onClick={() => setParams({ after: String(profiles.data!.next_after) })}>Next profiles</Button></div>
    </>}
    {needsRefresh && <p>Refresh profiles to load current routing.</p>}
    <Dialog open={confirmation !== null} onOpenChange={open => { if (!open && !save.isPending) setConfirmation(null) }} title="Save profile routing?"
      description={`For client #${clientId}, replace profile #${confirmation?.profile_id} routing with engine instances ${confirmation?.engine_ids.join(', ')}. Existing scan snapshots are preserved. A changed prior selection will be rejected.`}>
      <div className="report-actions"><Button variant="secondary" disabled={save.isPending} onClick={() => setConfirmation(null)}>Cancel</Button>
        <Button disabled={save.isPending} onClick={() => { if (confirmation) save.mutate(confirmation) }}>{save.isPending ? 'Saving…' : 'Confirm engine routing'}</Button></div>
    </Dialog>
  </section>
}
