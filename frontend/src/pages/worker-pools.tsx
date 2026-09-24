import { useState, type FormEvent } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import type { components } from '../lib/api.generated'
import { ChevronRight, Layers, Plus, RefreshCw } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Dialog } from '../components/ui/dialog'

type Pool = components['schemas']['PoolSummary']
type Values = components['schemas']['PoolUpdateBody']
type Action = { kind: 'create'; values: Values } | { kind: 'update'; id: number; values: Values } | { kind: 'delete'; id: number; name: string }

function PoolForm({ pool, busy, submit }: { pool?: Pool; busy: boolean; submit: (values: Values) => void }) {
  const [name, setName] = useState(pool?.name || '')
  const [selector, setSelector] = useState(pool?.selector || '')
  const [enabled, setEnabled] = useState(pool?.enabled ?? true)
  function save(event: FormEvent) { event.preventDefault(); submit({ name, selector, enabled }) }
  return <form onSubmit={save} aria-label={pool ? `Edit pool ${pool.id}` : 'Create worker pool'}>
    <fieldset disabled={busy || pool?.metadata_incomplete}>
      <label>Pool name<input required maxLength={100} value={name} onChange={event => setName(event.target.value)} /></label>
      <label>Label selector<textarea required maxLength={4096} value={selector} onChange={event => setSelector(event.target.value)} placeholder="site=istanbul,os=windows" /></label>
      {pool && <label>Pool state<select value={enabled ? 'enabled' : 'disabled'} onChange={event => setEnabled(event.target.value === 'enabled')}>
        <option value="enabled">Enabled</option><option value="disabled">Disabled</option></select></label>}
      <Button>{pool ? 'Save pool' : 'Create pool'}</Button>
    </fieldset>
  </form>
}

export default function WorkerPools({ session }: { session: Session }) {
  const client = useQueryClient()
  const [params, setParams] = useSearchParams()
  const after = params.get('after') || ''
  const [confirmation, setConfirmation] = useState<Action | null>(null)
  const [receipt, setReceipt] = useState('')
  const [editor, setEditor] = useState<{ pool?: Pool } | null>(null)
  const pools = useQuery({ queryKey: ['system-pools', after], queryFn: ({ signal }) => request('/api/ui/v1/system/pools', 'get', {
    query: new URLSearchParams({ limit: '20', ...(after ? { after } : {}) }), signal }),
    retry: false, gcTime: 60000, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })
  const action = useMutation({ retry: false, mutationFn: async (value: Action) => {
    if (value.kind === 'delete') {
      await request('/api/ui/v1/system/pools/{pool_id}', 'delete', { params: { pool_id: value.id }, csrf: session.csrf_token })
      return `Deleted pool #${value.id}.`
    }
    if (value.kind === 'create') {
      const result = await request('/api/ui/v1/system/pools', 'post', { csrf: session.csrf_token,
        body: { name: value.values.name, selector: value.values.selector } })
      return `Created pool #${result.id}. Assign engine instances from Engines.`
    }
    await request('/api/ui/v1/system/pools/{pool_id}', 'put', { params: { pool_id: value.id }, csrf: session.csrf_token, body: value.values })
    return `Updated pool #${value.id}.`
  }, onMutate: async () => { setReceipt(''); await client.cancelQueries({ queryKey: ['system-pools'] }) },
  onSuccess: message => setReceipt(message),
  onSettled: async () => { setConfirmation(null); setEditor(null); await Promise.all([
    client.invalidateQueries({ queryKey: ['system-pools'] }), client.invalidateQueries({ queryKey: ['engines'] }),
  ]) } })
  const busy = pools.isFetching || action.isPending
  return <section className="page management-page"><div className="page-heading"><div><p className="eyebrow">SYSTEM</p><h1>Worker pools</h1>
    <p className="muted">Route engine instances to workers with matching labels.</p></div>
    <div className="heading-actions"><Button variant="secondary" disabled={busy} onClick={() => { void pools.refetch() }}><RefreshCw size={14} aria-hidden="true" />Refresh pools</Button>
      <Button disabled={busy} onClick={() => setEditor({})}><Plus size={16} aria-hidden="true" />New pool</Button></div></div>
    <p className="callout">Every selector label must match exactly. Worker lifecycle, capacity and advertised adapters also apply.
      New pools are enabled and have no engine assignments. Disabling a pool stops new claims for its assigned engines; owned work finishes.
      Remove engine assignments before deleting a pool. A pool does not prove engine health or scan coverage.</p>
    {receipt && <p className="callout" role="status">{receipt}</p>}
    {action.error && <p className="error" role="alert">{action.error.message} The request may have reached the server. Refresh before trying again.</p>}
    {pools.isPending && <p role="status">Loading worker pools…</p>}
    {pools.error && <p className="error" role="alert">{pools.error.message}</p>}
    {!pools.error && pools.data && <>
      {pools.data.items.length > 0 && <ul className="entity-list" aria-label="Worker pools">{pools.data.items.map(pool => <li key={pool.id}>
        <button type="button" className="entity-row" disabled={busy} aria-label={`Manage pool ${pool.id}`} onClick={() => setEditor({ pool })}>
          <span className={`entity-avatar ${pool.enabled ? '' : 'is-muted'}`} aria-hidden="true"><Layers size={17} /></span>
          <span className="entity-identity"><strong>{pool.name}</strong><small>Pool #{pool.id}</small></span>
          <span className="entity-facts"><span title={pool.selector}><code>{pool.selector.length > 60 ? `${pool.selector.slice(0, 60)}…` : pool.selector}</code></span></span>
          <span className="entity-badges">{pool.metadata_incomplete && <span className="tag tag-danger">Metadata invalid</span>}
            <span className="tag">{pool.has_assignments ? 'Engines assigned' : 'No engines'}</span>
            <span className={`tag tag-dot ${pool.enabled ? 'tag-positive' : ''}`}>{pool.enabled ? 'Enabled' : 'Disabled'}</span></span>
          <ChevronRight className="entity-chevron" size={16} aria-hidden="true" />
        </button></li>)}</ul>}
      {!pools.data.items.length && <p className="empty">No worker pools on this page.</p>}
      <div className="history-pagination"><Button variant="secondary" disabled={!after || busy} onClick={() => setParams({})}>First pools</Button>
        <Button variant="secondary" disabled={!pools.data.next_after || busy} onClick={() => setParams({ after: String(pools.data!.next_after) })}>Next pools</Button></div></>}
    {editor && !confirmation && <Dialog open onOpenChange={open => { if (!open && !action.isPending) setEditor(null) }}
      title={editor.pool ? editor.pool.name : 'New worker pool'}
      description={editor.pool ? `Pool #${editor.pool.id} · ${editor.pool.has_assignments ? 'engine assignments present' : 'no engine assignments'}`
        : 'Use comma-separated key=value labels or a JSON object.'}>
      {editor.pool?.metadata_incomplete && <p role="alert" className="error">Pool metadata is invalid or exceeds the editor limit. Editing is unavailable to prevent saving incomplete routing settings.</p>}
      <PoolForm key={editor.pool?.id ?? 'new'} pool={editor.pool} busy={busy} submit={values => setConfirmation(editor.pool
        ? { kind: 'update', id: editor.pool.id, values } : { kind: 'create', values })} />
      {editor.pool && <div className="entity-dialog-section"><h3>Delete</h3>
        <p className="muted">{editor.pool.has_assignments ? 'Remove its engine assignments from Engines before deleting this pool.' : 'The server checks engine assignments again before deleting.'}</p>
        <Button variant="destructive" disabled={busy || editor.pool.has_assignments}
          onClick={() => setConfirmation({ kind: 'delete', id: editor.pool!.id, name: editor.pool!.name })}>Delete pool</Button></div>}
    </Dialog>}
    <Dialog open={confirmation !== null} onOpenChange={open => { if (!open && !action.isPending) { setConfirmation(null); setEditor(null) } }} title="Confirm pool change"
      description={confirmation?.kind === 'delete' ? `Delete ${confirmation.name} (#${confirmation.id})? The server checks engine assignments again.`
        : `${confirmation?.kind === 'create' ? 'Create enabled pool' : 'Update pool'} ${confirmation ? confirmation.values.name : ''}? Changes affect subsequent worker claims.`}>
      {confirmation && confirmation.kind !== 'delete' && <p className="pool-confirmation">Selector: {confirmation.values.selector}<br />State: {confirmation.values.enabled ? 'Enabled' : 'Disabled'}</p>}
      <div className="report-actions"><Button variant="secondary" disabled={action.isPending} onClick={() => { setConfirmation(null); setEditor(null) }}>Cancel</Button>
        <Button disabled={action.isPending} onClick={() => { if (confirmation) action.mutate(confirmation) }}>Confirm pool change</Button></div>
    </Dialog>
  </section>
}
