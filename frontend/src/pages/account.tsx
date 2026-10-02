import { ErrorMessage } from '../components/error-message'
import { useRef, useState, type FormEvent } from 'react'
import { useQuery } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import { Button } from '../components/ui/button'
import { Dialog } from '../components/ui/dialog'

export default function Account({ session, onPasswordChanged }: { session: Session; onPasswordChanged: () => void }) {
  const form = useRef<HTMLFormElement>(null)
  const sending = useRef(false)
  const [review, setReview] = useState(false)
  const [busy, setBusy] = useState(false)
  const [needsCheck, setNeedsCheck] = useState(false)
  const [error, setError] = useState('')
  const account = useQuery({ queryKey: ['account'], queryFn: ({ signal }) => request('/api/ui/v1/account', 'get', { signal }),
    retry: false, staleTime: 0, gcTime: 0, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })
  function clearPasswords() { form.current?.reset() }
  function cancel() { if (!busy) { clearPasswords(); setReview(false) } }
  function prepare(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setError('')
    const fields = event.currentTarget.elements
    if ((fields.namedItem('new_password') as HTMLInputElement).value !== (fields.namedItem('confirm_password') as HTMLInputElement).value) {
      setError('New password and confirmation must match.'); clearPasswords(); return
    }
    setReview(true)
  }
  async function changePassword() {
    if (sending.current || !review || !form.current) return
    sending.current = true; setBusy(true); setError('')
    const fields = form.current.elements
    const body = {
      current_password: (fields.namedItem('current_password') as HTMLInputElement).value,
      new_password: (fields.namedItem('new_password') as HTMLInputElement).value,
      confirm_password: (fields.namedItem('confirm_password') as HTMLInputElement).value,
    }
    clearPasswords()
    try {
      await request('/api/ui/v1/account/password', 'post', { csrf: session.csrf_token, body })
      onPasswordChanged()
    } catch (failure) {
      setError(`${failure instanceof Error ? failure.message : 'Password change failed.'} If the response was interrupted, the password may have changed. Check your session before another attempt; if signed out, try signing in with the new password.`)
    } finally {
      setNeedsCheck(true); setReview(false); setBusy(false); sending.current = false
    }
  }
  return <section className="page management-page"><div className="page-heading"><div>
    <p className="eyebrow">YOUR ACCOUNT</p><h1>Account</h1><p className="muted">Manage your own sign-in password.</p></div>
    <Button variant="secondary" disabled={busy || review || account.isFetching} onClick={async () => {
      clearPasswords(); const result = await account.refetch(); if (!result.isError) setNeedsCheck(false)
    }}>Check session</Button></div>
    {error && <p role="alert" className="error"><ErrorMessage message={error} /></p>}
    {account.isPending && <p role="status">Loading account...</p>}
    {account.error && <p role="alert" className="error"><ErrorMessage message={account.error.message || ''} /></p>}
    {!account.error && account.data && <>
      <section className="settings-panel" aria-label="Profile"><div className="settings-panel-header"><div><h2>Profile</h2>
        <p>Who you are signed in as. Roles are assigned by an administrator{account.data.auth_source !== 'local' ? ' or your directory' : ''}.</p></div></div>
        <dl className="property-list"><div><dt>Username</dt><dd>{account.data.username}</dd></div>
          <div><dt>Role</dt><dd><span className="tag">{account.data.role}</span></dd></div>
          <div><dt>Sign-in source</dt><dd>{account.data.auth_source === 'local' ? 'Local MASP account' : `Directory (${account.data.auth_source})`}</dd></div></dl></section>
      {account.data.auth_source !== 'local' ? <p className="callout">Your password is managed by the directory. Contact your directory administrator to change it.</p> :
        <form ref={form} className="settings-panel" aria-label="Change your password" onSubmit={prepare}>
          <div className="settings-panel-header"><div><h2>Change password</h2>
            <p>Use a different password of 8 to 4096 characters. All your MASP sessions will be signed out, including this one.</p></div></div>
          <fieldset disabled={busy || review || needsCheck || account.isFetching}>
            <div className="settings-panel-body form-rows">
              <label>Current password<input name="current_password" type="password" autoComplete="current-password" required maxLength={4096} /></label>
              <label>New password<input name="new_password" type="password" autoComplete="new-password" required minLength={8} maxLength={4096} /></label>
              <label>Confirm new password<input name="confirm_password" type="password" autoComplete="new-password" required minLength={8} maxLength={4096} /></label>
            </div>
            <div className="settings-panel-footer"><Button type="submit">Review password change</Button></div>
          </fieldset>
        </form>}
    </>}
    <Dialog open={review} onOpenChange={open => { if (!open) cancel() }} title="Change your password?"
      description="This signs out all your MASP sessions. You will need the new password to sign in again.">
      <div className="report-actions"><Button variant="secondary" disabled={busy} onClick={cancel}>Cancel</Button>
        <Button disabled={busy} onClick={() => { void changePassword() }}>{busy ? 'Changing...' : 'Confirm password change'}</Button></div>
    </Dialog>
  </section>
}
