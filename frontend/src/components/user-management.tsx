import { useRef, useState, type FormEvent } from 'react'
import type { components } from '../lib/api.generated'
import { request, type Session } from '../lib/api'
import { Button } from './ui/button'
import { Dialog } from './ui/dialog'

type User = components['schemas']['UserSummary']
export function UserManagement({ user, session, onClose, onComplete }: {
  user: User; session: Session; onClose: () => void; onComplete: (message: string, error: string) => void
}) {
  const secret = useRef<HTMLInputElement>(null)
  const sending = useRef(false)
  const [busy, setBusy] = useState(false)
  const [review, setReview] = useState<{ action: 'update' | 'delete'; role: 'admin' | 'analyst'; reset: boolean } | null>(null)
  function clear() { if (secret.current) secret.current.value = '' }
  function cancel() { if (!busy) { clear(); onClose() } }
  function prepare(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setReview({ action: 'update', role: (event.currentTarget.elements.namedItem('role') as HTMLSelectElement).value as 'admin' | 'analyst', reset: Boolean(secret.current?.value) })
  }
  async function send() {
    if (!review || sending.current) return
    sending.current = true; setBusy(true)
    const password = secret.current?.value || null
    clear()
    try {
      if (review.action === 'delete') await request('/api/ui/v1/users/{user_id}', 'delete', {
        params: { user_id: user.id }, csrf: session.csrf_token, body: { expected_revision: user.management_revision },
      })
      else await request('/api/ui/v1/users/{user_id}', 'put', {
        params: { user_id: user.id }, csrf: session.csrf_token,
        body: { expected_revision: user.management_revision, role: review.role, password },
      })
      onComplete(`User #${user.id} ${review.action === 'delete' ? 'removed' : 'updated'}. Refresh the user list before another action.`, '')
    } catch (failure) {
      onComplete('', `${failure instanceof Error ? failure.message : 'User management failed.'} If the response was interrupted, the action may have completed. Refresh and check the account before another attempt.`)
    } finally { sending.current = false; setBusy(false) }
  }
  return <Dialog open onOpenChange={open => { if (!open) cancel() }} title={review ? 'Confirm user action' : 'Manage user'}
    description={`${user.username} (#${user.id}) — ${user.role}, ${user.auth_source}`}>
    <form onSubmit={prepare} hidden={review !== null} aria-label="Edit user">
      {user.auth_source === 'local' && <fieldset disabled={busy}>
        <label>Account role<select name="role" defaultValue={user.role}><option value="analyst">Analyst</option><option value="admin">Administrator</option></select></label>
        <label>Replacement password<input ref={secret} type="password" minLength={8} maxLength={4096} autoComplete="new-password" /></label>
        <p className="muted">Leave blank to keep the password. A replacement signs out all sessions for this account.</p>
        <Button type="submit">Review changes</Button>
      </fieldset>}
      {user.auth_source !== 'local' && <p className="callout">Directory roles and passwords cannot be edited here. Removing this local record signs out its current MASP sessions but does not disable the directory account. It may return on the next directory sign-in.</p>}
      <div className="report-actions"><Button type="button" variant="secondary" onClick={cancel}>Cancel</Button>
        <Button type="button" variant="destructive" onClick={() => { clear(); setReview({ action: 'delete', role: user.role as 'admin' | 'analyst', reset: false }) }}>Review removal</Button></div>
    </form>
    {review && <><p>{review.action === 'delete' ? 'Remove this user record and its MASP sessions?' : `Set role to ${review.role}.${review.reset ? ' Replace the password and sign out all sessions.' : ' Keep the current password.'}`}</p>
      {review.action === 'delete' && user.auth_source !== 'local' && <p>Directory access is unchanged. The record may return on the next directory sign-in.</p>}
      <div className="report-actions"><Button variant="secondary" disabled={busy} onClick={cancel}>Cancel</Button>
        <Button variant={review.action === 'delete' ? 'destructive' : 'default'} disabled={busy} onClick={() => { void send() }}>
          {busy ? 'Saving...' : review.action === 'delete' ? 'Confirm removal' : 'Confirm changes'}</Button></div></>}
  </Dialog>
}
