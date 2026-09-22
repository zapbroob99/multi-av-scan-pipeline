import { useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import type { components } from '../lib/api.generated'
import { Button } from '../components/ui/button'
import { Dialog } from '../components/ui/dialog'

type Values = components['schemas']['ScanPolicyBody']

export default function ScanPolicy({ session }: { session: Session }) {
  const [confirmation, setConfirmation] = useState<Values | null>(null)
  const [needsRefresh, setNeedsRefresh] = useState(false)
  const [version, setVersion] = useState(0)
  const policy = useQuery({ queryKey: ['scan-policy'], queryFn: ({ signal }) => request('/api/ui/v1/scan-policy', 'get', { signal }),
    retry: false, gcTime: 0, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })
  const save = useMutation({ retry: false, mutationFn: (body: Values) => request('/api/ui/v1/scan-policy', 'put', { csrf: session.csrf_token, body }),
    onSettled: () => { setConfirmation(null); setNeedsRefresh(true) } })
  const busy = policy.isFetching || save.isPending || confirmation !== null
  function review(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    setConfirmation({ api_max_wait_seconds: String(form.get('api_max_wait_seconds') || ''),
      api_retry_after_seconds: String(form.get('api_retry_after_seconds') || ''), upload_max_bytes: String(form.get('upload_max_bytes') || '') })
  }
  return <section className="page management-page"><div className="page-heading"><div><p className="eyebrow">ADMINISTRATION</p><h1>Scan policy</h1>
    <p className="muted">Operational limits for REST scan requests and file intake.</p></div>
    <Button variant="secondary" disabled={busy} onClick={async () => { save.reset(); const result = await policy.refetch();
      if (!result.error) { setNeedsRefresh(false); setVersion(value => value + 1) } }}>Reload policy</Button></div>
    <nav className="report-actions"><Link to="/system/overview">System overview</Link></nav>
    <p className="callout">Changes apply to subsequent policy reads without a restart. Blank fields clear database overrides and use the environment or built-in default.
      An upload size cap of 0 removes this policy cap; deployment HTTP body limits still apply. ICAP and deployment settings are configured separately.</p>
    <p className="muted">Saving replaces all three overrides. Coordinate edits with other administrators; the last successful save wins.</p>
    {policy.isPending && <p role="status">Loading scan policy…</p>}
    {policy.error && <p role="alert" className="error">{policy.error.message}</p>}
    {save.isSuccess && <p role="status" className="callout">Scan policy saved. Reload policy to see the effective values.</p>}
    {save.error && <p role="alert" className="error">{save.error.message} The request may have reached the server. Reload and check the values before another save; this request will not be replayed.</p>}
    {needsRefresh && <p>Reload policy before editing again.</p>}
    {!needsRefresh && !policy.error && policy.data && <form key={version} onSubmit={review} aria-label="Scan policy settings">
      <fieldset disabled={busy}>{policy.data.fields.map(field => <section className="submission-card" key={field.key}>
        <label htmlFor={`policy-${field.key}`}>{field.label}{field.unit && ` (${field.unit})`}</label>
        <p className="muted">{field.help}</p>
        <input id={`policy-${field.key}`} name={field.key} type="number" step="1" min={field.minimum} max={field.maximum}
          defaultValue={field.override_raw} placeholder={`Default: ${field.default}`} />
        <p className="muted">Effective: <strong>{field.value.toLocaleString()}</strong> · {field.source}</p>
      </section>)}<Button type="submit">Review policy changes</Button></fieldset>
    </form>}
    <Dialog open={confirmation !== null} onOpenChange={open => { if (!open && !save.isPending) setConfirmation(null) }} title="Save scan policy?"
      description="Apply these three overrides together. Blank entries revert to the environment or built-in default.">
      <dl className="report-metadata">{policy.data?.fields.map(field => <div key={field.key}><dt>{field.label}</dt>
        <dd>{confirmation?.[field.key as keyof Values] || 'Clear override'}</dd></div>)}</dl>
      <div className="report-actions"><Button variant="secondary" disabled={save.isPending} onClick={() => setConfirmation(null)}>Cancel</Button>
        <Button disabled={save.isPending} onClick={() => { if (confirmation) save.mutate(confirmation) }}>{save.isPending ? 'Saving…' : 'Confirm policy changes'}</Button></div>
    </Dialog>
  </section>
}
