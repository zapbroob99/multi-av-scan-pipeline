import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import type { components } from '../lib/api.generated'
import { Button } from '../components/ui/button'
import { Dialog } from '../components/ui/dialog'

type Worker = components['schemas']['WorkerSummary']
type Lifecycle = components['schemas']['WorkerLifecycleBody']['lifecycle_state']
type Action = { kind: 'lifecycle'; node_id: string; lifecycle_state: Lifecycle } | { kind: 'revoke'; node_id: string }

function WorkerCard({ worker, busy, confirm }: { worker: Worker; busy: boolean; confirm: (action: Action) => void }) {
  const [lifecycle, setLifecycle] = useState<Lifecycle | ''>('')
  return <article className="submission-card report-engine" aria-label={`Worker ${worker.node_id}`}>
    <div className="history-heading"><div><h2>{worker.display_name}</h2><small>{worker.node_id}</small></div>
      <span className={`health-pill ${worker.online ? '' : 'health-unavailable'}`}>{worker.online ? 'Online' : 'Offline'}</span></div>
    <dl className="report-metadata"><dt>Lifecycle</dt><dd>{worker.lifecycle_state}</dd>
      <dt>Host / platform</dt><dd>{worker.hostname} / {worker.platform}</dd>
      <dt>Agent version</dt><dd>{worker.agent_version}</dd>
      <dt>Configured capacity</dt><dd>{worker.capacity}</dd>
      <dt>Last reported runtime</dt><dd>{worker.runtime_state}</dd>
      <dt>Last reported scan</dt><dd>{worker.active_scan_id === null ? 'None' : `#${worker.active_scan_id}`}</dd>
      <dt>Heartbeat age</dt><dd>{worker.age_seconds.toLocaleString()} seconds</dd>
      <dt>Advertised adapters</dt><dd>{worker.engine_keys.join(', ') || 'None recorded'}</dd>
      <dt>Labels</dt><dd>{Object.entries(worker.labels).map(([key, value]) => `${key}=${value}`).join(', ') || 'None recorded'}</dd></dl>
    {worker.metadata_incomplete && <p role="alert" className="error">Labels or adapter metadata are invalid or exceed the display limit. Check the worker configuration.</p>}
    <div className="worker-actions"><label>Lifecycle for {worker.node_id}<select value={lifecycle} disabled={busy}
      onChange={event => setLifecycle(event.target.value as Lifecycle | '')}>
      <option value="">Choose a new lifecycle</option>
      {(['active', 'draining', 'disabled'] as const).map(state => <option key={state} value={state}>{state}</option>)}
    </select></label><Button disabled={busy || !lifecycle || lifecycle === worker.lifecycle_state}
      onClick={() => { if (lifecycle) confirm({ kind: 'lifecycle', node_id: worker.node_id, lifecycle_state: lifecycle }) }}>Apply lifecycle</Button>
      <Button variant="destructive" disabled={busy} onClick={() => confirm({ kind: 'revoke', node_id: worker.node_id })}>Revoke agent credentials</Button></div>
  </article>
}

export default function System({ session }: { session: Session }) {
  const client = useQueryClient()
  const [params, setParams] = useSearchParams()
  const after = params.get('after') || ''
  const [confirmation, setConfirmation] = useState<Action | null>(null)
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
    setConfirmation(null)
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
      <div className="report-engines">{workers.data.items.map(worker => <WorkerCard key={`${worker.node_id}-${worker.lifecycle_state}`} worker={worker} busy={busy} confirm={setConfirmation} />)}</div>
      <div className="history-pagination"><Button variant="secondary" disabled={!after || busy} onClick={() => setParams({})}>First workers</Button>
        <Button variant="secondary" disabled={!workers.data.next_after || busy} onClick={() => setParams({ after: workers.data!.next_after! })}>Next workers</Button></div>
    </>}
    <Dialog open={confirmation !== null} onOpenChange={open => { if (!open && !action.isPending) setConfirmation(null) }}
      title={confirmation?.kind === 'revoke' ? 'Revoke agent credentials?' : 'Change worker lifecycle?'}
      description={confirmation?.kind === 'revoke'
        ? `Revoke all current agent credentials for ${confirmation.node_id}. Running Control API work loses authorization. The node must enroll again.`
        : `Set ${confirmation?.node_id} to ${confirmation?.kind === 'lifecycle' ? confirmation.lifecycle_state : ''}. Active allows new claims; draining or disabled stops new claims while owned work finishes.`}>
      <div className="report-actions"><Button variant="secondary" disabled={action.isPending} onClick={() => setConfirmation(null)}>Cancel</Button>
        <Button disabled={action.isPending} onClick={() => { if (confirmation) action.mutate(confirmation) }}>{action.isPending ? 'Saving…' : 'Confirm worker action'}</Button></div>
    </Dialog>
  </section>
}
