import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { request } from '../lib/api'
import { Button } from './ui/button'
import { ErrorMessage } from './error-message'
import { Timestamp } from './timestamp'

export function EngineUsage({ instanceId }: { instanceId: number }) {
  const [after, setAfter] = useState<number | null>(null)
  const query = useQuery({ queryKey: ['engine-usage', instanceId, after],
    queryFn: ({ signal }) => request('/api/ui/v1/engines/{instance_id}/usage', 'get', {
      params: { instance_id: instanceId }, query: new URLSearchParams(after ? { after: String(after) } : {}), signal,
    }), retry: false, gcTime: 0, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })
  const data = !query.error && !query.isFetching ? query.data : undefined
  return <section aria-label="Engine profile references">
    <p className="muted">Current profiles that name this engine. Disabled clients and profiles are included. Manual scans and accepted routing snapshots are not listed here.</p>
    {query.isFetching && <p role="status">Reading profile references…</p>}
    {query.error && <p role="alert" className="error"><ErrorMessage message={query.error.message} /></p>}
    {data && <><p className="muted">Read <Timestamp value={new Date(data.observed_at * 1000).toISOString()} />. Each page is a separate current read.</p>
      {!data.profiles.length && <p>No current profile references on this page. This does not prove the engine is unused by scans.</p>}
      <ul className="engine-usage-list">{data.profiles.map(profile => <li key={profile.profile_id}>
        <Link to={`/service-clients/${profile.client_id}/overview?profile_id=${profile.profile_id}`}>{profile.client_name} / {profile.profile_name}</Link>
        <p className="muted">{profile.is_default ? 'Default profile' : 'Named profile'}{!profile.client_enabled && ' · client disabled'}{!profile.profile_enabled && ' · profile disabled'}{profile.names_truncated && ' · names shortened'}</p>
      </li>)}</ul></>}
    <div className="report-actions"><Button variant="secondary" disabled={query.isFetching} onClick={() => void query.refetch()}>Refresh references</Button>
      <Button variant="secondary" disabled={!after || query.isFetching} onClick={() => setAfter(null)}>First references</Button>
      <Button variant="secondary" disabled={!data?.next_after || query.isFetching} onClick={() => setAfter(data!.next_after)}>Next references</Button></div>
  </section>
}

export function EngineUsageDisclosure({ instanceId }: { instanceId: number }) {
  const [open, setOpen] = useState(false)
  return <details className="rule-preview" onToggle={event => setOpen(event.currentTarget.open)}>
    <summary>Profiles using this engine</summary>{open && <EngineUsage instanceId={instanceId} />}
  </details>
}
