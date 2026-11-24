import { ErrorMessage } from '../components/error-message'
import { useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import type { components } from '../lib/api.generated'
import { formatBytes } from '../lib/storage'
import { Button } from '../components/ui/button'
import { Dialog } from '../components/ui/dialog'
import { ConfigurationContext } from '../components/configuration-context'

type Values = components['schemas']['ScanPolicyBody']
type Field = components['schemas']['ScanPolicyField']

const MIB = 1024 * 1024

/** A stored byte count as the MiB text the size control edits. */
function toMib(raw: string) {
  if (!raw.trim()) return ''
  const bytes = Number(raw)
  return Number.isFinite(bytes) ? String(bytes / MIB) : raw
}

/** What a value means to an operator, for the effective line and the confirmation. */
function describe(field: Field, value: number) {
  if (field.control === 'switch') return value ? 'On' : 'Off'
  if (field.control === 'size') return value ? formatBytes(value) : 'No limit'
  return `${value.toLocaleString()}${field.unit ? ` ${field.unit}` : ''}`
}

/** Fallback is resolved by the backend in the API process, even with an override. */
function fallback(field: Field) {
  return describe(field, field.fallback_value)
}

function sourceLabel(source: string) {
  if (source === 'database override') return 'Set here'
  if (source.startsWith('environment')) return 'Server setting'
  return 'Default'
}

export default function ScanPolicy({ session, area = 'all', embedded = false }: { session: Session; area?: 'limits' | 'notifications' | 'all'; embedded?: boolean }) {
  const title = area === 'limits' ? 'Limits & API behavior' : area === 'notifications' ? 'Event selection' : 'System limits & notifications'
  const [confirmation, setConfirmation] = useState<Values | null>(null)
  const [needsRefresh, setNeedsRefresh] = useState(false)
  const [version, setVersion] = useState(0)
  const [error, setError] = useState('')
  const policy = useQuery({ queryKey: ['scan-policy'], queryFn: ({ signal }) => request('/api/ui/v1/scan-policy', 'get', { signal }),
    retry: false, gcTime: 0, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })
  // A successful save is followed by a fresh read, so the form shows what is now in effect.
  // An uncertain outcome is never replayed: the operator reloads and checks first.
  const save = useMutation({ retry: false, mutationFn: (body: Values) => {
    if (area === 'notifications') return request('/api/ui/v1/notification-policy', 'put', { csrf: session.csrf_token, body: { siem_not_allowed_events: body.siem_not_allowed_events } })
    if (area === 'limits') return request('/api/ui/v1/operational-policy', 'put', { csrf: session.csrf_token,
      body: { api_max_wait_seconds: body.api_max_wait_seconds, api_retry_after_seconds: body.api_retry_after_seconds, upload_max_bytes: body.upload_max_bytes } })
    return request('/api/ui/v1/scan-policy', 'put', { csrf: session.csrf_token, body })
  },
    onSuccess: async () => { const result = await policy.refetch(); if (result.error) setNeedsRefresh(true); else setVersion(value => value + 1) },
    onError: () => setNeedsRefresh(true),
    onSettled: () => setConfirmation(null) })
  const busy = policy.isFetching || save.isPending || confirmation !== null
  const fields = (policy.data?.fields ?? []).filter(field => area === 'all' || (area === 'notifications') === (field.key === 'siem_not_allowed_events'))
  const httpCeiling = policy.data?.deployment_http_ceiling_bytes
  function review(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    const form = new FormData(event.currentTarget)
    const values: Record<string, string> = {}
    // Only this task area's fields are written; other settings retain their current values.
    for (const field of fields) {
      const raw = String(form.get(field.key) || '').trim()
      if (field.control === 'size' && raw) {
        // An untouched control must not round an existing byte count on save.
        if (raw === toMib(field.override_raw)) { values[field.key] = field.override_raw; continue }
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
  return <section className={embedded ? 'settings-workspace-section' : 'page management-page'}><div className="page-heading"><div>
    {embedded ? <h2>{title}</h2> : <h1>{title}</h1>}
    <p className="muted">{area === 'notifications' ? 'Choose which additional scan outcomes produce SIEM events. Delivery status and retries are below.' : 'Limits for API and console uploads and API response timing. File rules belong to scan profiles.'}</p></div>
    <Button variant="secondary" disabled={busy} onClick={async () => { save.reset(); setError(''); const result = await policy.refetch();
      if (!result.error) { setNeedsRefresh(false); setVersion(value => value + 1) } }}>Reload</Button></div>
    {!embedded && <nav className="report-actions"><Link to="/policies/profiles">Scan profiles</Link><Link to="/configuration">Configuration guide</Link></nav>}
    {policy.isPending && <p role="status">Loading settings…</p>}
    {policy.error && <p role="alert" className="error"><ErrorMessage message={policy.error.message || ''} /></p>}
    {save.isSuccess && !needsRefresh && <p role="status" className="callout">Settings saved. The values below are the ones now in effect.</p>}
    {save.error && <p role="alert" className="error"><ErrorMessage message={save.error.message || ''} /> The request may have reached the server. Reload and check the values before another save; this request will not be replayed.</p>}
    {needsRefresh && <p>Reload before editing again.</p>}
    {!needsRefresh && !policy.error && policy.data && <form key={version} className="settings-panel" onSubmit={review} aria-label={area === 'all' ? 'System limits and notifications' : title}>
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
          <p className="setting-effective">In effect <strong>{describe(field, field.value)}</strong><span className="tag" title={field.source}>{sourceLabel(field.source)}</span></p>
          <ConfigurationContext context={field.context} />
          {field.key === 'upload_max_bytes' && <ConfigurationContext context={policy.data.deployment_http_context} title="HTTP ceiling scope and application" />}
          {field.key === 'upload_max_bytes' && httpCeiling != null && <p className="setting-note">
            This can only make uploads smaller: a separate deployment ceiling of <strong>{formatBytes(httpCeiling)}</strong>{' '}
            (<code>MASP_HTTP_UPLOAD_MAX_BYTES</code>) always applies as well, and 0 here does not raise or remove it.</p>}
          {field.key === 'upload_max_bytes' && policy.data.deployment_http_ceiling_valid === false && <p role="alert" className="error">
            The deployment HTTP body ceiling is invalid. Uploads are refused. Correct MASP_HTTP_UPLOAD_MAX_BYTES on the API deployment and recreate/restart the affected service; saving this form cannot repair that setting.</p>}</div>
      </div>)}</div>
      {error && <p role="alert" className="error">{error}</p>}
      <div className="settings-panel-footer"><p>Saving replaces the values in this form; the last save wins.</p><Button type="submit">Review changes</Button></div></fieldset>
    </form>}
    <Dialog open={confirmation !== null} onOpenChange={open => { if (!open && !save.isPending) setConfirmation(null) }} title="Save these settings?"
      description="The displayed values are saved together. Blank ones go back to the server setting or default.">
      <p className="muted">After-save values below use this API process's current environment. Other processes may use different environment fallbacks when an override is removed.</p>
      <dl className="preview-limits">{fields.map(field => <div key={field.key}><dt>{field.label}</dt>
        <dd><p>Current: <strong>{describe(field, field.value)}</strong> · {sourceLabel(field.source)}</p>
          <p>After save: <strong>{shown(field, confirmation?.[field.key as keyof Values])}</strong></p>
          <p className="muted">{field.context?.applies}</p></dd></div>)}</dl>
      <div className="report-actions"><Button variant="secondary" disabled={save.isPending} onClick={() => setConfirmation(null)}>Cancel</Button>
        <Button disabled={save.isPending} onClick={() => { if (confirmation) save.mutate(confirmation) }}>{save.isPending ? 'Saving…' : 'Save settings'}</Button></div>
    </Dialog>
  </section>
}
