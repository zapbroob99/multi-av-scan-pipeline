import { useRef, useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import { Button } from '../components/ui/button'
import { Dialog } from '../components/ui/dialog'
import { UserManagement } from '../components/user-management'
import type { components } from '../lib/api.generated'

export default function Users({ session }: { session: Session }) {
  const [params, setParams] = useSearchParams()
  const after = params.get('after') || ''
  const secret = useRef<HTMLInputElement>(null)
  const form = useRef<HTMLFormElement>(null)
  const sending = useRef(false)
  const [review, setReview] = useState<{ username: string; role: 'admin' | 'analyst' } | null>(null)
  const [busy, setBusy] = useState(false)
  const [needsRefresh, setNeedsRefresh] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [editing, setEditing] = useState<components['schemas']['UserSummary'] | null>(null)
  const users = useQuery({ queryKey: ['users', after],
    queryFn: ({ signal }) => request('/api/ui/v1/users', 'get', { query: new URLSearchParams(after ? { after } : {}), signal }),
    retry: false, staleTime: 0, gcTime: 0, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })
  const locked = busy || review !== null || editing !== null
  function cancel() { if (!busy) { setReview(null); if (secret.current) secret.current.value = '' } }
  function prepare(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const controls = event.currentTarget.elements
    setReview({ username: (controls.namedItem('username') as HTMLInputElement).value.trim(),
      role: (controls.namedItem('role') as HTMLSelectElement).value as 'admin' | 'analyst' })
  }
  async function create() {
    if (!review || sending.current) return
    sending.current = true; setBusy(true); setMessage(''); setError('')
    const password = secret.current?.value || ''
    if (secret.current) secret.current.value = ''
    try {
      const result = await request('/api/ui/v1/users', 'post', { csrf: session.csrf_token, body: { ...review, password } })
      setMessage(`Local user #${result.user_id} created. Refresh the list to review accounts.`)
      form.current?.reset()
    } catch (failure) {
      setError(`${failure instanceof Error ? failure.message : 'Creation failed.'} If the response was interrupted, the account may have been created. Refresh and check the user list before another attempt.`)
    } finally {
      setNeedsRefresh(true); setReview(null); setBusy(false); sending.current = false
    }
  }
  return <section className="page management-page"><div className="page-heading"><div><p className="eyebrow">ACCESS MANAGEMENT</p>
    <h1>Users</h1><p className="muted">Local accounts and directory identities.</p></div>
    <Button variant="secondary" disabled={locked || users.isFetching} onClick={async () => {
      const result = await users.refetch(); if (!result.isError) setNeedsRefresh(false)
    }}>Refresh users</Button></div>
    {message && <p role="status" className="callout">{message}</p>}
    {error && <p role="alert" className="error">{error}</p>}
    <form ref={form} className="submission-card" onSubmit={prepare} aria-label="Create local user">
      <h2>Create local user</h2><fieldset disabled={locked || needsRefresh}>
        <label>Username<input name="username" required maxLength={128} autoComplete="off" /></label>
        <label>Role<select name="role" defaultValue="analyst"><option value="analyst">Analyst</option><option value="admin">Administrator</option></select></label>
        <label>Initial password<input ref={secret} type="password" name="password" required minLength={8} maxLength={4096} autoComplete="new-password" /></label>
        <Button type="submit">Review new user</Button>
      </fieldset><p className="muted">At least 8 characters. The password is cleared on cancellation or submission and is never displayed in the confirmation.</p>
    </form>
    <p className="callout">Directory roles and passwords are managed by the directory. Removing a directory record does not disable directory access.
      Use <Link to="/account">Account</Link> to change your own local password.</p>
    {users.isPending && <p role="status">Loading users…</p>}
    {users.error && <p role="alert" className="error">{users.error.message}</p>}
    {!users.error && !needsRefresh && users.data && <>
      {users.data.items.map(user => <article className="submission-card" key={user.id}>
        <h2>{user.username}{user.username_truncated ? '…' : ''}{user.id === session.user.id ? ' (you)' : ''}</h2>
        <p>#{user.id} · {user.role} · {user.auth_source === 'ldap' ? 'LDAP — directory managed' : user.auth_source}</p>
        {user.display_name && <p>{user.display_name}</p>}
        <p className="muted">Created: {user.created_at} · Last login: {user.last_login_at || 'Not recorded'}</p>
        {user.id !== session.user.id && <Button variant="secondary" disabled={locked || users.isFetching} onClick={() => {
          if (secret.current) secret.current.value = ''; setEditing(user)
        }}>Manage user #{user.id}</Button>}
      </article>)}
      {!users.data.items.length && <p>No users on this page.</p>}
      <div className="history-pagination"><Button variant="secondary" disabled={locked || users.isFetching || !after} onClick={() => setParams({})}>First page</Button>
        <Button variant="secondary" disabled={locked || users.isFetching || !users.data.next_after} onClick={() => setParams({ after: String(users.data!.next_after) })}>Next page</Button></div>
    </>}
    <Dialog open={review !== null} onOpenChange={open => { if (!open) cancel() }} title="Create local user?"
      description={`Create ${review?.username || ''} with ${review?.role || ''} access. LDAP users must be managed in the directory.`}>
      <div className="report-actions"><Button variant="secondary" disabled={busy} onClick={cancel}>Cancel</Button>
        <Button disabled={busy} onClick={() => { void create() }}>{busy ? 'Creating…' : 'Confirm creation'}</Button></div>
    </Dialog>
    {editing && <UserManagement user={editing} session={session} onClose={() => setEditing(null)} onComplete={(receipt, failure) => {
      setEditing(null); setNeedsRefresh(true); setMessage(receipt); setError(failure)
    }} />}
  </section>
}
