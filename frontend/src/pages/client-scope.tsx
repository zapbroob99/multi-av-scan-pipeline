import { lazy, Suspense, useCallback, useState, type FormEvent } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import { ClientWorkspace, type ClientTab } from '../components/client-workspace'
import { Button } from '../components/ui/button'
import { ErrorMessage } from '../components/error-message'

const Profiles = lazy(() => import('./client-profiles'))
const Storage = lazy(() => import('./client-storage'))

/** A single client-scoped editor, reachable from its task area or the client dialog. */
export default function ClientScope({ kind, session }: { kind: 'profiles' | 'storage'; session: Session }) {
  const { clientId: rawId } = useParams()
  const id = rawId ? Number(rawId) : null
  const valid = id !== null && Number.isSafeInteger(id) && id > 0
  const base = kind === 'storage' ? '/storage/access' : '/policies/profiles'
  const [params, setParams] = useSearchParams()
  const navigate = useNavigate()
  const [guards, setGuards] = useState<Record<string, boolean>>({})
  const guard = useCallback((panel: string, blocked: boolean) => setGuards(previous => ({ ...previous, [panel]: blocked })), [])
  const blocked = Object.values(guards).some(Boolean)
  const clients = useQuery({ queryKey: ['scope-clients', kind, params.toString()], enabled: id === null,
    queryFn: ({ signal }) => request('/api/ui/v1/service-clients', 'get', { query: new URLSearchParams({ ...(params.get('q') ? { q: params.get('q')! } : {}), ...(params.get('after') ? { after: params.get('after')! } : {}) }), signal }),
    retry: false, gcTime: 0, refetchOnWindowFocus: false, refetchOnReconnect: false })
  const client = useQuery({ queryKey: ['scope-client', id], enabled: valid,
    queryFn: ({ signal }) => request('/api/ui/v1/service-clients/{client_id}', 'get', { params: { client_id: id! }, signal }),
    retry: false, gcTime: 0, refetchOnWindowFocus: false, refetchOnReconnect: false })
  if (rawId && !valid) return <section className="page"><h1>Invalid connected system</h1><Link to={base}>Choose a connected system</Link></section>
  function search(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const q = String(new FormData(event.currentTarget).get('q') || '').trim()
    setParams(q ? { q } : {})
  }
  function select(tab: ClientTab) { if (!blocked && id) navigate(tab === 'profiles' ? `/policies/profiles/${id}` : tab === 'storage' ? `/storage/access/${id}` : `/service-clients/${id}/${tab === 'settings' ? 'overview' : tab}`) }
  if (id === null) return <section className="page management-page">
    <div className="page-heading"><div><h1>{kind === 'storage' ? 'Sources & access' : 'Scan profiles'}</h1>
      <p className="muted">{kind === 'storage' ? 'Choose which connected system may read from a storage source. Source roots and mounts are managed in the deployment.' : 'Profiles belong to a connected system. Choose one to manage its rules and default profile.'}</p></div>
      <Link className="button button-secondary" to="/service-clients/new">Add connected system</Link></div>
    <form className="toolbar" onSubmit={search}><label className="search"><input aria-label="Find connected system" name="q" maxLength={100} defaultValue={params.get('q') || ''} placeholder="Name or client key" /></label><Button type="submit" variant="secondary">Search</Button></form>
    {clients.isPending && <p role="status">Loading connected systems…</p>}
    {clients.error && <p role="alert"><ErrorMessage message={clients.error.message} /></p>}
    {!clients.error && clients.data && <><ul className="scope-client-list">{clients.data.items.map(item => <li key={item.id}>
      <Link to={`${base}/${item.id}`}><strong>{item.display_name}{item.metadata_incomplete && ' (name truncated)'}</strong><span className="muted">{item.client_key}{!item.enabled && ' · disabled'}{item.managed && ' · deployment managed'}</span></Link>
    </li>)}</ul>{!clients.data.items.length && <p>No connected systems match this page. Adjust the search or add a connected system.</p>}
      <div className="report-actions"><Button variant="secondary" disabled={!params.has('after') || clients.isFetching} onClick={() => { const next = new URLSearchParams(params); next.delete('after'); setParams(next) }}>First systems</Button>
        <Button variant="secondary" disabled={!clients.data.next_after || clients.isFetching} onClick={() => { const next = new URLSearchParams(params); next.set('after', String(clients.data!.next_after)); setParams(next) }}>Next systems</Button></div></>}
  </section>
  return <div className="scope-workspace">
    <div className="scope-context"><div><span className="muted">Connected system</span><strong>{client.data?.display_name ?? `#${id}`}</strong>
      {client.data && <small>{client.data.client_key}{client.data.enabled ? '' : ' · disabled'}</small>}</div>
      <Button variant="secondary" disabled={blocked} onClick={() => navigate(base)}>Change connected system</Button></div>
    {client.isPending && <p role="status">Loading connected system…</p>}
    {client.error && <p role="alert"><ErrorMessage message={client.error.message} /></p>}
    {!client.error && client.data && <ClientWorkspace.Provider value={{ mode: 'route', clientId: id, tab: kind, select, guard }}>
      <Suspense fallback={<p role="status">Loading editor…</p>}>{kind === 'storage' ? <Storage session={session} /> : <Profiles session={session} />}</Suspense>
    </ClientWorkspace.Provider>}
  </div>
}
