import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Cpu, Plus, Search, RefreshCw, Settings2, Trash2, FlaskConical, FileCode2 } from 'lucide-react'
import { request, pollInterval, type Adapter, type Engine, type Health, type Session } from '../lib/api'
import { Button } from '../components/ui/button'
import { Dialog } from '../components/ui/dialog'

export function ConfigFields({ adapter, values, onChange, editing = false }: {
  adapter: Adapter; values: Record<string, string>; onChange: (key: string, value: string) => void; editing?: boolean
}) {
  return <div className="field-grid">{adapter.fields.filter(field => {
    if (adapter.key !== 'clamav') return true
    if (['host', 'port'].includes(field.key)) return values.mode === 'clamd'
    if (field.key === 'command') return values.mode === 'cli'
    return true
  }).map(field => <label key={field.key}>
    {field.label}{field.secret && editing && <small>Leave blank to keep the saved key</small>}
    {field.choices.length ? <select value={values[field.key] || ''} required onChange={e => onChange(field.key, e.target.value)}>
      <option value="">Select {field.label}</option>
      {field.choices.map(value => <option key={value} value={value}>{value}</option>)}
    </select> : <input type={field.secret ? 'password' : field.field_type === 'number' ? 'number' : 'text'}
      value={values[field.key] || ''} placeholder={field.default} required={!(field.secret && editing)}
      autoComplete={field.secret ? 'new-password' : 'off'} maxLength={4096}
      onChange={e => onChange(field.key, e.target.value)} />}
  </label>)}</div>
}

function RuleManager({ engine, session }: { engine: Engine; session: Session }) {
  const client = useQueryClient()
  const [error, setError] = useState('')
  const [filename, setFilename] = useState('')
  const [content, setContent] = useState('')
  const params = { instance_id: engine.id }, csrf = session.csrf_token
  const query = useQuery({ queryKey: ['rules', engine.id], queryFn: ({ signal }) => request('/api/ui/v1/engines/{instance_id}/rules', 'get', { params, signal }) })
  const mutation = useMutation({ mutationFn: (action: () => Promise<unknown>) => action(), onSuccess: () => {
    void client.invalidateQueries({ queryKey: ['rules', engine.id] })
    void client.invalidateQueries({ queryKey: ['engines'] })
  } })
  async function act(task: () => Promise<unknown>) {
    setError('')
    try { await mutation.mutateAsync(task); return true }
    catch (e) { setError((e as Error).message); return false }
  }
  return <div className="rules-panel">
    <p className="callout">Rules are managed on the MASP host. Remote workers still require the configured rules to be deployed to their own host.</p>
    {(error || query.error) && <p className="error" role="alert">{error || query.error?.message}</p>}
    {query.isPending && <p role="status">Loading rules…</p>}
    <ul className="rule-list">{query.data?.rules.map(rule => <li key={rule.name}><span>{rule.name}<small>{rule.enabled ? 'Enabled' : 'Disabled'} · {rule.size_bytes} bytes</small></span>
      <Button variant="secondary" disabled={mutation.isPending} onClick={() => void act(() => request('/api/ui/v1/engines/{instance_id}/rules/{name}/toggle', 'post', { params: { ...params, name: rule.name }, csrf }))}>Toggle</Button>
      <Button variant="destructive" disabled={mutation.isPending} onClick={() => {
        if (window.confirm(`Delete rule ${rule.name}? This removes the file from MASP.`)) void act(() => request('/api/ui/v1/engines/{instance_id}/rules/{name}', 'delete', { params: { ...params, name: rule.name }, csrf }))
      }}>Delete</Button></li>)}</ul>
    <form onSubmit={async e => { e.preventDefault(); if (await act(() => request('/api/ui/v1/engines/{instance_id}/rules', 'post', { params, csrf, body: { filename, content } }))) { setFilename(''); setContent('') } }}>
      <label>Rule file (UTF-8, up to 96 KiB)<input type="file" accept=".yar,.yara" onChange={async e => {
        const file = e.target.files?.[0]; if (!file) return
        if (file.size > 96 * 1024) { setError('Rule exceeds the 96 KiB console limit.'); return }
        try { setContent(await file.text()); setFilename(file.name); setError('') } catch { setError('Unable to read this rule file.') }
      }} /></label>
      <label>Filename<input value={filename} onChange={e => setFilename(e.target.value)} placeholder="rules.yar" required /></label>
      <label>Rule source<textarea value={content} onChange={e => setContent(e.target.value)} required rows={7} /></label>
      <p className="muted">Saving an existing filename replaces its content. Saving does not prove the rules compile; run an engine check.</p>
      <Button disabled={mutation.isPending}>{mutation.isPending ? 'Saving…' : 'Save rule'}</Button>
    </form>
  </div>
}

export default function Engines({ session }: { session: Session }) {
  const client = useQueryClient()
  const [search, setSearch] = useState('')
  const [adding, setAdding] = useState(false)
  const [editing, setEditing] = useState<Engine | null>(null)
  const [deleting, setDeleting] = useState<Engine | null>(null)
  const [rulesEngine, setRulesEngine] = useState<Engine | null>(null)
  const [adapterKey, setAdapterKey] = useState('')
  const [name, setName] = useState('')
  const [config, setConfig] = useState<Record<string, string>>({})
  const [notice, setNotice] = useState<{ error: boolean; text: string } | null>(null)
  const [formError, setFormError] = useState('')
  const [localChecks, setLocalChecks] = useState<Record<number, Health>>({})
  const query = useQuery({ queryKey: ['engines'], queryFn: ({ signal }) => request('/api/ui/v1/engines', 'get', { signal }),
    refetchInterval: query => pollInterval(query.state.data), refetchIntervalInBackground: false,
    refetchOnWindowFocus: true,
  })
  const mutation = useMutation({ mutationFn: (task: () => Promise<unknown>) => task() })
  const inventory = query.data
  const selected = inventory?.adapters.find(a => a.key === adapterKey)
  const csrf = session.csrf_token

  async function perform(task: () => Promise<unknown>, message: string) {
    setNotice(null); setFormError('')
    // Cancel older GETs so an old successful probe cannot overwrite a newly requested one.
    await client.cancelQueries({ queryKey: ['engines'] })
    try {
      await mutation.mutateAsync(task)
      setNotice({ error: false, text: message })
      await client.invalidateQueries({ queryKey: ['engines'] })
      return true
    } catch (e) {
      const text = (e as Error).message
      setNotice({ error: true, text }); setFormError(text); return false
    }
  }
  async function save(event: FormEvent) {
    event.preventDefault()
    if (!selected) return
    const success = await perform(() => editing
      ? request('/api/ui/v1/engines/{instance_id}/config', 'put', { params: { instance_id: editing.id }, csrf, body: { config } })
      : request('/api/ui/v1/engines', 'post', { csrf, body: { adapter_key: selected.key, display_name: name, config } }),
      editing ? 'Settings saved. Previous health was invalidated; a new worker check is required.' : 'Engine instance created. Connection health has not yet been verified.')
    if (success) {
      if (editing) setLocalChecks(previous => { const next = { ...previous }; delete next[editing.id]; return next })
      setAdding(false); setEditing(null)
    }
  }
  function edit(engine: Engine) {
    setEditing(engine); setAdapterKey(engine.adapter_key); setConfig(engine.config); setName(engine.display_name); setFormError('')
  }
  async function check(engine: Engine, adapter: Adapter) {
    let result: Health | undefined
    const success = await perform(async () => {
      result = await request('/api/ui/v1/engines/{instance_id}/checks', 'post', { params: { instance_id: engine.id }, csrf })
    }, 'Worker check requested. Waiting for the worker result; this is not a connection success.')
    if (success && result) {
      if (adapter.capabilities.deployment !== 'worker') {
        setLocalChecks(previous => ({ ...previous, [engine.id]: result! }))
        setNotice({ error: !result.ok, text: result.detail })
      } else if (result.state === 'unavailable') setNotice({ error: true, text: result.detail })
    }
  }
  if (query.isPending) return <section className="page"><h1>Engine deployments</h1><div className="skeleton" role="status">Loading engine inventory…</div></section>
  if (!inventory) return <section className="page"><h1>Engines unavailable</h1><p role="alert" className="error">{query.error?.message}</p><Button onClick={() => void query.refetch()}>Retry</Button></section>
  const engines = inventory.engines.filter(e => `${e.display_name} ${e.adapter_key}`.toLowerCase().includes(search.toLowerCase()))
  return <section className="page">
    <div className="page-heading"><div><p className="eyebrow">SCAN INFRASTRUCTURE</p><h1>Engine deployments</h1><p className="muted">Configure your engines. Verify their health. Keep every scan accountable.</p></div>
      <Button onClick={() => { setAdding(true); setEditing(null); setAdapterKey(''); setName(''); setConfig({}); setFormError('') }}><Plus size={17} />Add engine</Button></div>
    <div className="stats-row"><div><span>Configured</span><strong>{inventory.engines.length}</strong></div><div><span>Enabled</span><strong>{inventory.engines.filter(e => e.enabled).length}</strong></div><div><span>Needs attention</span><strong>{inventory.engines.filter(e => e.enabled && ['failed', 'unavailable'].includes(e.health.state)).length}</strong></div></div>
    {notice && <div role={notice.error ? 'alert' : 'status'} className={notice.error ? 'notice error' : 'notice'}>{notice.text}</div>}
    {query.error && <div className="notice error" role="alert">Inventory refresh failed. Displayed results may be stale: {query.error.message}</div>}
    <div className="toolbar"><label className="search"><Search size={18} /><input aria-label="Search engines" placeholder="Search engine deployments…" value={search} onChange={e => setSearch(e.target.value)} /></label>
      <Button variant="secondary" disabled={query.isFetching || mutation.isPending} onClick={() => void query.refetch()}><RefreshCw size={16} />{query.isFetching ? 'Refreshing…' : 'Refresh'}</Button></div>
    {!engines.length && <div className="empty"><Cpu size={36} /><h2>{inventory.engines.length ? 'No matching deployments' : 'Your first engine starts here'}</h2><p className="muted">Add a named adapter instance and explicitly configure its runtime.</p></div>}
    <div className="engine-grid">{engines.map(engine => {
      const adapter = inventory.adapters.find(a => a.key === engine.adapter_key)!
      const health = engine.enabled ? localChecks[engine.id] || engine.health : engine.health
      return <article className="engine-card" key={engine.id}>
        <div className="card-heading"><div className="engine-icon"><Cpu size={23} /></div><div><h2>{engine.display_name}</h2><p className="muted">{adapter.label} <span>· #{engine.id}</span></p></div><span className={`health-pill health-${health.state}`}>{health.state}</span></div>
        <div className="tags"><span>{adapter.support_state}</span><span>{adapter.capabilities.deployment}</span>{adapter.capabilities.consumes_external_quota && <span>External quota · manual only</span>}</div>
        <p className="health-detail">{health.detail}</p><p className="checked-at">{health.checked_at ? `Last checked ${new Date(health.checked_at * 1000).toLocaleString()}` : 'No verified check timestamp'}</p>
        <label className="placement">Worker pool<select aria-label={`Worker pool for ${engine.display_name}`} disabled={mutation.isPending} value={engine.pool_id ?? ''} onChange={e => void perform(() => request('/api/ui/v1/engines/{instance_id}/placement', 'put', { params: { instance_id: engine.id }, csrf, body: { pool_id: e.target.value ? Number(e.target.value) : null } }), 'Worker placement saved. Health will be checked again.')}>
          <option value="">Unbound · adapter-compatible workers</option>{inventory.pools.map(pool => <option value={pool.id} key={pool.id}>{pool.name}{pool.enabled ? '' : ' (disabled)'}</option>)}
        </select></label>
        <div className="card-actions"><Button variant="secondary" disabled={mutation.isPending || !engine.enabled} onClick={() => void check(engine, adapter)}><FlaskConical size={16} />Test connection</Button>
          <Button variant="secondary" disabled={mutation.isPending} onClick={() => edit(engine)} aria-label={`Settings for ${engine.display_name}`}><Settings2 size={16} />Settings</Button>
          {adapter.capabilities.supports_rules && <Button variant="secondary" onClick={() => setRulesEngine(engine)}><FileCode2 size={16} />Rules</Button>}
        </div><div className="card-footer"><Button variant="secondary" disabled={mutation.isPending} onClick={() => void perform(() => request('/api/ui/v1/engines/{instance_id}/enabled', 'put', { params: { instance_id: engine.id }, csrf, body: { enabled: !engine.enabled } }), `${engine.display_name} ${engine.enabled ? 'disabled' : 'enabled'}.`)}>{engine.enabled ? 'Disable' : 'Enable'}</Button>
          <Button variant="destructive" disabled={mutation.isPending} onClick={() => setDeleting(engine)} aria-label={`Remove ${engine.display_name}`}><Trash2 size={15} /></Button></div>
      </article>
    })}</div>
    <p className="migration-note">New console · Existing scans and integrations are unchanged. <a href="/engines">Open legacy Engines</a></p>
    <Dialog open={adding || !!editing} onOpenChange={open => { if (!open && !mutation.isPending) { setAdding(false); setEditing(null) } }} title={editing ? `Configure ${editing.display_name}` : 'Add engine deployment'} description="Select a vendor adapter and supply its configuration. Suggested values are placeholders, not saved defaults.">
      {!editing && <div className="adapter-picker">{inventory.adapters.filter(a => a.capabilities.allows_multiple_instances || !inventory.engines.some(e => e.adapter_key === a.key)).map(adapter =>
        <button key={adapter.key} type="button" aria-label={`${adapter.label} ${adapter.support_state}`} aria-pressed={adapterKey === adapter.key} onClick={() => { setAdapterKey(adapter.key); setConfig({}); setFormError('') }}><strong>{adapter.label}</strong><small>{adapter.support_state}</small></button>)}</div>}
      {selected && <form onSubmit={save}><p className="callout">{selected.description}</p>
        {!editing && <label>Deployment name<input value={name} onChange={e => setName(e.target.value)} maxLength={128} placeholder="e.g. Defender Windows Pool A" required /></label>}
        <ConfigFields adapter={selected} values={config} editing={!!editing?.has_secret} onChange={(key, value) => setConfig(previous => ({ ...previous, [key]: value }))} />
        {formError && <p role="alert" className="error">{formError}</p>}
        <div className="dialog-actions"><Button variant="secondary" type="button" disabled={mutation.isPending} onClick={() => { setAdding(false); setEditing(null) }}>Cancel</Button><Button disabled={mutation.isPending}>{mutation.isPending ? 'Saving…' : editing ? 'Save settings' : 'Create deployment'}</Button></div>
      </form>}
    </Dialog>
    <Dialog open={!!deleting} onOpenChange={open => { if (!open && !mutation.isPending) setDeleting(null) }} title="Remove engine deployment?" description="Historical jobs keep their original identity. Jobs from this instance will not be rebound to another deployment.">
      {formError && <p role="alert" className="error">{formError}</p>}
      <p>Remove <strong>{deleting?.display_name}</strong>?</p><div className="dialog-actions"><Button variant="secondary" onClick={() => setDeleting(null)}>Cancel</Button><Button variant="destructive" disabled={mutation.isPending} onClick={async () => {
        if (deleting && await perform(() => request('/api/ui/v1/engines/{instance_id}', 'delete', { params: { instance_id: deleting.id }, csrf }), 'Engine deployment removed.')) setDeleting(null)
      }}>Remove deployment</Button></div>
    </Dialog>
    <Dialog open={!!rulesEngine} onOpenChange={open => { if (!open) setRulesEngine(null) }} title="YARA rules" description="Manage the local rule files for this configured YARA instance.">{rulesEngine && <RuleManager engine={rulesEngine} session={session} />}</Dialog>
  </section>
}
