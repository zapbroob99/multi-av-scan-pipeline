import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import type { components } from '../lib/api.generated'
import { ChevronRight, Server } from 'lucide-react'
import { shortAge } from '../lib/utils'
import { Button } from '../components/ui/button'
import { Dialog } from '../components/ui/dialog'

type Worker = components['schemas']['WorkerSummary']
type Lifecycle = components['schemas']['WorkerLifecycleBody']['lifecycle_state']
type Action = { kind: 'lifecycle'; node_id: string; lifecycle_state: Lifecycle } | { kind: 'revoke'; node_id: string }

const LIFECYCLE_TAG: Record<string, string> = { active: 'tag-positive', draining: 'tag-warning', disabled: 'tag-danger' }

function WorkerRow({ worker, busy, open }: { worker: Worker; busy: boolean; open: (worker: Worker) => void }) {
  const running = worker.active_scan_id !== null
  return <li><button type="button" className="entity-row" disabled={busy} aria-label={`Manage worker ${worker.node_id}`} onClick={() => open(worker)}>
    <span className={`entity-avatar ${worker.online ? 'is-positive' : 'is-muted'}`} aria-hidden="true"><Server size={17} /></span>
    <span className="entity-identity"><strong>{worker.display_name}</strong><small>{worker.node_id} · {worker.hostname} / {worker.platform}</small></span>
    <span className="entity-facts"><span>Heartbeat {shortAge(worker.age_seconds)} ago</span>
      <span>Capacity {worker.capacity}</span>
      <span>{running ? `Scanning #${worker.active_scan_id}` : worker.runtime_state}</span>
      <span>{worker.engine_keys.length} adapter{worker.engine_keys.length === 1 ? '' : 's'}</span></span>
    <span className="entity-badges">{worker.metadata_incomplete && <span className="tag tag-danger">Metadata invalid</span>}
      <span className={`tag ${LIFECYCLE_TAG[worker.lifecycle_state] || ''}`}>{worker.lifecycle_state}</span>
      <span className={`tag tag-dot ${worker.online ? 'tag-positive' : ''}`}>{worker.online ? 'Online' : 'Offline'}</span></span>
    <ChevronRight className="entity-chevron" size={16} aria-hidden="true" />
  </button></li>
}

function WorkerDialog({ worker, busy, close, confirm }: { worker: Worker; busy: boolean; close: () => void; confirm: (action: Action) => void }) {
  const [lifecycle, setLifecycle] = useState<Lifecycle | ''>('')
  return <Dialog open onOpenChange={open => { if (!open) close() }} title={worker.display_name}
    description={`${worker.node_id} · ${worker.online ? 'Online' : 'Offline'} · lifecycle ${worker.lifecycle_state}`}>
    <dl className="report-metadata entity-dialog-facts"><dt>Host / platform</dt><dd>{worker.hostname} / {worker.platform}</dd>
      <dt>Agent version</dt><dd>{worker.agent_version}</dd>
      <dt>Configured capacity</dt><dd>{worker.capacity}</dd>
      <dt>Last reported runtime</dt><dd>{worker.runtime_state}</dd>
      <dt>Last reported scan</dt><dd>{worker.active_scan_id === null ? 'None' : `#${worker.active_scan_id}`}</dd>
      <dt>Heartbeat age</dt><dd>{worker.age_seconds.toLocaleString()} seconds</dd>
      <dt>Advertised adapters</dt><dd>{worker.engine_keys.join(', ') || 'None recorded'}</dd>
      <dt>Labels</dt><dd>{Object.entries(worker.labels).map(([key, value]) => `${key}=${value}`).join(', ') || 'None recorded'}</dd></dl>
    {worker.metadata_incomplete && <p role="alert" className="error">Labels or adapter metadata are invalid or exceed the display limit. Check the worker configuration.</p>}
    <div className="entity-dialog-section"><h3>Lifecycle</h3><div className="entity-inline-controls">
      <label>Lifecycle for {worker.node_id}<select value={lifecycle} disabled={busy} onChange={event => setLifecycle(event.target.value as Lifecycle | '')}>
        <option value="">Choose a new lifecycle</option>
        {(['active', 'draining', 'disabled'] as const).map(state => <option key={state} value={state}>{state}</option>)}
      </select></label>
      <Button disabled={busy || !lifecycle || lifecycle === worker.lifecycle_state}
        onClick={() => { if (lifecycle) confirm({ kind: 'lifecycle', node_id: worker.node_id, lifecycle_state: lifecycle }) }}>Apply lifecycle</Button></div></div>
    <div className="entity-dialog-section"><h3>Agent access</h3>
      <p className="muted">Revoking signs the node out of the Control API; it must enroll again.</p>
      <Button variant="destructive" disabled={busy} onClick={() => confirm({ kind: 'revoke', node_id: worker.node_id })}>Revoke agent credentials</Button></div>
  </Dialog>
}

export default function System({ session }: { session: Session }) {
  const client = useQueryClient()
  const [params, setParams] = useSearchParams()
  const after = params.get('after') || ''
  const [confirmation, setConfirmation] = useState<Action | null>(null)
  const [selected, setSelected] = useState<Worker | null>(null)
  const [receipt, setReceipt] = useState('')
  const workers = useQuery({ queryKey: ['system-workers', after],
    queryFn: ({ signal }) => request('/api/ui/v1/system/workers', 'get', {
      query: new URLSearchParams({ limit: '20', ...(after ? { after } : {}) }), signal }),
    retry: false, gcTime: 60000, refetchOnMount: 'always', refetchOnWindowFocus: false,
    refetchInterval: confirmation ? false : 30000, refetchIntervalInBackground: false })
  const action = useMutation({ retry: false, mutationFn: async (value: Action) => {
    if (value.kind === 'lifecycle') {
      await request('/api/ui/v1/system/workers/lifecycle', 'post', { csrf: session.csrf_token,
        body: { node_id: value.node_id, lifecycle_state: value.lifecycle_state } })
      return `Lifecycle for ${value.node_id} changed to ${value.lifecycle_state}.`
    }
    const result = await request('/api/ui/v1/system/workers/credentials/revoke', 'post', {
      csrf: session.csrf_token, body: { node_id: value.node_id } })
    return `Revoked ${result.revoked_count} agent credential(s) for ${value.node_id}. Control API access requires enrollment again.`
  }, onMutate: async () => {
    setReceipt('')
    await client.cancelQueries({ queryKey: ['system-workers'] })
  }, onSuccess: message => setReceipt(message), onSettled: async () => {
    setConfirmation(null); setSelected(null)
    await Promise.all([client.invalidateQueries({ queryKey: ['system-workers'] }), client.invalidateQueries({ queryKey: ['engines'] })])
  } })
  const busy = workers.isFetching || action.isPending
  return <section className="page"><div className="page-heading"><div><p className="eyebrow">SYSTEM</p><h1>Managed worker nodes</h1>
    <p className="muted">Worker identity, heartbeat and lifecycle controls.</p></div>
    <Button variant="secondary" disabled={busy} onClick={() => { void workers.refetch() }}>Refresh workers</Button></div>
    <p className="callout">Heartbeat indicates liveness, not engine health. Active nodes may claim work when capacity and pool rules permit.
      Draining and disabled nodes finish owned work but do not claim new jobs. Last reported runtime is not a complete list of node activity.</p>
    {receipt && <p role="status" className="callout">{receipt}</p>}
    {action.error && <p role="alert" className="error">{action.error.message} The request may have reached the server. Refresh before trying again.</p>}
    {workers.isPending && <p role="status">Loading worker nodes…</p>}
    {workers.error && <p role="alert" className="error">{workers.error.message}</p>}
    {!workers.error && workers.data && <>
      <p className="muted">{workers.data.items.length} shown. A heartbeat expires after {workers.data.stale_after_seconds} seconds. Refreshes every 30 seconds.</p>
      {workers.data.items.length === 0 && <p className="empty">No worker nodes on this page.</p>}
      {workers.data.items.length > 0 && <ul className="entity-list" aria-label="Worker nodes">{workers.data.items.map(worker =>
        <WorkerRow key={`${worker.node_id}-${worker.lifecycle_state}`} worker={worker} busy={busy} open={setSelected} />)}</ul>}
      <div className="history-pagination"><Button variant="secondary" disabled={!after || busy} onClick={() => setParams({})}>First workers</Button>
        <Button variant="secondary" disabled={!workers.data.next_after || busy} onClick={() => setParams({ after: workers.data!.next_after! })}>Next workers</Button></div>
    </>}
    {selected && !confirmation && <WorkerDialog key={selected.node_id} worker={selected} busy={busy} close={() => setSelected(null)}
      confirm={action => setConfirmation(action)} />}
    <Dialog open={confirmation !== null} onOpenChange={open => { if (!open && !action.isPending) { setConfirmation(null); setSelected(null) } }}
      title={confirmation?.kind === 'revoke' ? 'Revoke agent credentials?' : 'Change worker lifecycle?'}
      description={confirmation?.kind === 'revoke'
        ? `Revoke all current agent credentials for ${confirmation.node_id}. Running Control API work loses authorization. The node must enroll again.`
        : `Set ${confirmation?.node_id} to ${confirmation?.kind === 'lifecycle' ? confirmation.lifecycle_state : ''}. Active allows new claims; draining or disabled stops new claims while owned work finishes.`}>
      <div className="report-actions"><Button variant="secondary" disabled={action.isPending} onClick={() => { setConfirmation(null); setSelected(null) }}>Cancel</Button>
        <Button disabled={action.isPending} onClick={() => { if (confirmation) action.mutate(confirmation) }}>{action.isPending ? 'Saving…' : 'Confirm worker action'}</Button></div>
    </Dialog>
  </section>
}
