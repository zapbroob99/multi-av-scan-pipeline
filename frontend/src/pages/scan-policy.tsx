import { ErrorMessage } from '../components/error-message'
import { useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import type { components } from '../lib/api.generated'
import { formatBytes } from '../lib/storage'
import { Button } from '../components/ui/button'
import { Dialog } from '../components/ui/dialog'

type Values = components['schemas']['ScanPolicyBody']
type Field = components['schemas']['ScanPolicyField']

const MIB = 1024 * 1024

/** A stored byte count as the MiB text the size control edits. */
function toMib(raw: string) {
  if (!raw.trim()) return ''
  const bytes = Number(raw)
  return Number.isFinite(bytes) ? String(Math.round(bytes / MIB * 100) / 100) : raw
}

/** What a value means to an operator, for the effective line and the confirmation. */
function describe(field: Field, value: number) {
  if (field.control === 'switch') return value ? 'On' : 'Off'
  if (field.control === 'size') return value ? formatBytes(value) : 'No limit'
  return `${value.toLocaleString()}${field.unit ? ` ${field.unit}` : ''}`
}

/** What a blank field falls back to; the server setting is only visible while nothing is set here. */
function fallback(field: Field) {
  return field.override_raw ? `server setting, else ${describe(field, field.default)}` : describe(field, field.value)
}

function sourceLabel(source: string) {
  if (source === 'database override') return 'Set here'
  if (source.startsWith('environment')) return 'Server setting'
  return 'Default'
}

export default function ScanPolicy({ session }: { session: Session }) {
  const [confirmation, setConfirmation] = useState<Values | null>(null)
  const [needsRefresh, setNeedsRefresh] = useState(false)
  const [version, setVersion] = useState(0)
  const [error, setError] = useState('')
  const policy = useQuery({ queryKey: ['scan-policy'], queryFn: ({ signal }) => request('/api/ui/v1/scan-policy', 'get', { signal }),
    retry: false, gcTime: 0, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })
  // A successful save is followed by a fresh read, so the form shows what is now in effect.
  // An uncertain outcome is never replayed: the operator reloads and checks first.
  const save = useMutation({ retry: false, mutationFn: (body: Values) => request('/api/ui/v1/scan-policy', 'put', { csrf: session.csrf_token, body }),
    onSuccess: async () => { const result = await policy.refetch(); if (result.error) setNeedsRefresh(true); else setVersion(value => value + 1) },
    onError: () => setNeedsRefresh(true),
    onSettled: () => setConfirmation(null) })
  const busy = policy.isFetching || save.isPending || confirmation !== null
  const fields = policy.data?.fields ?? []
  function review(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    const form = new FormData(event.currentTarget)
    const values: Record<string, string> = {}
    // Every field the server lists is sent; the strict body names each one.
    for (const field of fields) {
      const raw = String(form.get(field.key) || '').trim()
      if (field.control === 'size' && raw) {
        const mib = Number(raw)
        if (!Number.isFinite(mib) || mib < 0) { setError(`${field.label}: enter a size in MiB, 0 for no limit, or leave it blank.`); return }
        values[field.key] = String(Math.round(mib * MIB))
      } else values[field.key] = raw
    }
    setConfirmation(values as Values)
  }
  function shown(field: Field, raw: string | undefined) {
    if (!raw) return `Not set here (${fallback(field)})`
    return describe(field, Number(raw))
  }
  return <section className="page management-page"><div className="page-heading"><div><p className="eyebrow">ADMINISTRATION</p><h1>System limits &amp; notifications</h1>
    <p className="muted">Limits for API and console uploads, and which outcomes reach SIEM. Client file rules are set per client, under Scan profiles.</p></div>
    <Button variant="secondary" disabled={busy} onClick={async () => { save.reset(); setError(''); const result = await policy.refetch();
      if (!result.error) { setNeedsRefresh(false); setVersion(value => value + 1) } }}>Reload</Button></div>
    <nav className="report-actions"><Link to="/system/overview">System overview</Link><Link to="/service-clients">Service clients</Link></nav>
    {policy.isPending && <p role="status">Loading settings…</p>}
    {policy.error && <p role="alert" className="error"><ErrorMessage message={policy.error.message || ''} /></p>}
    {save.isSuccess && !needsRefresh && <p role="status" className="callout">Settings saved. The values below are the ones now in effect.</p>}
    {save.error && <p role="alert" className="error"><ErrorMessage message={save.error.message || ''} /> The request may have reached the server. Reload and check the values before another save; this request will not be replayed.</p>}
    {needsRefresh && <p>Reload before editing again.</p>}
    {!needsRefresh && !policy.error && policy.data && <form key={version} className="settings-panel" onSubmit={review} aria-label="System limits and notifications">
      <div className="settings-panel-header"><div><h2>Settings</h2><p>Leave a field blank to use the server setting or the built-in default. Changes apply without a restart.</p></div></div>
      <fieldset disabled={busy}><div className="settings-panel-body">{fields.map(field => <div className="setting-row" key={field.key}>
        <div className="setting-label"><label htmlFor={`policy-${field.key}`}>{field.label}{field.control === 'size' ? ' (MiB)' : field.unit && ` (${field.unit})`}</label>
          <p id={`policy-${field.key}-help`}>{field.help}</p></div>
        <div className="setting-control">
          {field.control === 'switch'
            ? <select id={`policy-${field.key}`} name={field.key} defaultValue={field.override_raw} aria-describedby={`policy-${field.key}-help`}>
                <option value="">Not set here ({fallback(field)})</option><option value="1">On</option><option value="0">Off</option></select>
            : <input id={`policy-${field.key}`} name={field.key} aria-describedby={`policy-${field.key}-help`}
                {...field.control === 'size'
                  ? { inputMode: 'decimal' as const, defaultValue: toMib(field.override_raw), placeholder: `Not set: ${fallback(field)}` }
                  : { type: 'number', step: 1, min: field.minimum, max: field.maximum, defaultValue: field.override_raw, placeholder: `Not set: ${fallback(field)}` }} />}
          <p className="setting-effective">In effect <strong>{describe(field, field.value)}</strong><span className="tag" title={field.source}>{sourceLabel(field.source)}</span></p></div>
      </div>)}</div>
      {error && <p role="alert" className="error">{error}</p>}
      <div className="settings-panel-footer"><p>Saving replaces every value set here; the last save wins.</p><Button type="submit">Review changes</Button></div></fieldset>
    </form>}
    <Dialog open={confirmation !== null} onOpenChange={open => { if (!open && !save.isPending) setConfirmation(null) }} title="Save these settings?"
      description="All values are saved together. Blank ones go back to the server setting or default.">
      <dl className="report-metadata">{fields.map(field => <div key={field.key}><dt>{field.label}</dt>
        <dd>{shown(field, confirmation?.[field.key as keyof Values])}</dd></div>)}</dl>
      <div className="report-actions"><Button variant="secondary" disabled={save.isPending} onClick={() => setConfirmation(null)}>Cancel</Button>
        <Button disabled={save.isPending} onClick={() => { if (confirmation) save.mutate(confirmation) }}>{save.isPending ? 'Saving…' : 'Save settings'}</Button></div>
    </Dialog>
  </section>
}
