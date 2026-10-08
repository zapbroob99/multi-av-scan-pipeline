import { useState, type FormEvent } from 'react'
import { request, type Session } from '../lib/api'
import { Button } from './ui/button'
import { Dialog } from './ui/dialog'
import { ErrorMessage } from './error-message'

export const EXPIRY: [string, string][] = [['', 'Never (until revoked)'], ['7', '7 days'], ['30', '30 days'], ['90', '90 days'], ['365', '1 year']]

export type ExceptionTarget = { sha256: string; filename: string; clientId: number | null; clientName?: string | null }

/** Add an exception for one file straight from where it was seen (a ledger row
 * or a report). The dialog is the confirmation: it names the exact file and
 * scope, and nothing is sent until the administrator presses Add exception.
 * No automatic retry: an uncertain outcome is resolved on the Exceptions page. */
export function ExceptionDialog({ target, session, onClose, onAdded }: {
  target: ExceptionTarget | null; session: Session; onClose: () => void; onAdded: (id: number, target: ExceptionTarget) => void
}) {
  const [scope, setScope] = useState<'client' | 'all'>('client')
  const [reason, setReason] = useState('')
  const [expiry, setExpiry] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const clientScoped = target?.clientId != null && scope === 'client'

  function close() {
    if (busy) return
    setReason(''); setExpiry(''); setScope('client'); setError('')
    onClose()
  }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!target || busy) return
    if (!reason.trim()) { setError('A reason is required.'); return }
    setBusy(true); setError('')
    try {
      const created = await request('/api/ui/v1/exceptions', 'post', { csrf: session.csrf_token, body: {
        sha256: target.sha256, reason: reason.trim(), service_client_id: clientScoped ? target.clientId : null,
        expires_in_days: expiry ? Number(expiry) : null } })
      setReason(''); setExpiry(''); setScope('client')
      onAdded(created.id, target)
    } catch (e) {
      setError(`${(e as Error).message} Check System > Exceptions before trying again.`)
    } finally { setBusy(false) }
  }

  return <Dialog open={target !== null} locked={busy} onOpenChange={open => { if (!open) close() }} title="Add an exception for this file?"
    description="Later copies of this exact file are allowed for the scope you choose, even when an engine or a rule would block them. No detection alert is raised for them. Scans already recorded keep their decisions.">
    {target && <form onSubmit={submit} aria-label="Exception for this file"><fieldset disabled={busy}>
      <p className="cell-name" title={target.filename}>{target.filename}</p>
      <p><code className="hash-value">{target.sha256}</code></p>
      <label>Applies to<select value={target.clientId == null ? 'all' : scope} disabled={busy || target.clientId == null}
        onChange={e => setScope(e.target.value as 'client' | 'all')}>
        {target.clientId != null && <option value="client">Only #{target.clientId} {target.clientName || 'this client'}</option>}
        <option value="all">All clients and manual scans</option></select></label>
      <label>Reason<input value={reason} maxLength={500} disabled={busy} onChange={e => setReason(e.target.value)} aria-describedby="exception-dialog-reason" /></label>
      <p id="exception-dialog-reason" className="muted">Why this file is harmless, for example the ticket or the vendor confirmation.</p>
      <label>Expires<select value={expiry} disabled={busy} onChange={e => setExpiry(e.target.value)}>
        {EXPIRY.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
      {error && <p role="alert" className="error"><ErrorMessage message={error} /></p>}
      <div className="report-actions"><Button type="button" variant="secondary" disabled={busy} onClick={close}>Cancel</Button>
        <Button type="submit" disabled={busy}>{busy ? 'Adding…' : 'Add exception'}</Button></div>
    </fieldset></form>}
  </Dialog>
}
