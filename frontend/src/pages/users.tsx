import { useRef, useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ChevronRight, Plus, RefreshCw } from 'lucide-react'
import { request, type Session } from '../lib/api'
import { sinceRecorded } from '../lib/utils'
import { Button } from '../components/ui/button'
import { Dialog } from '../components/ui/dialog'
import { UserManagement } from '../components/user-management'
import type { components } from '../lib/api.generated'

type User = components['schemas']['UserSummary']

function initials(user: User) {
  const source = (user.display_name || user.username).trim()
  const parts = source.split(/[\s._-]+/).filter(Boolean)
  return (parts.length > 1 ? parts[0][0] + parts[1][0] : source.slice(0, 2)) || '?'
}

export default function Users({ session }: { session: Session }) {
  const [params, setParams] = useSearchParams()
  const after = params.get('after') || ''
  const secret = useRef<HTMLInputElement>(null)
  const sending = useRef(false)
  const [creating, setCreating] = useState(false)
  const [review, setReview] = useState<{ username: string; role: 'admin' | 'analyst' } | null>(null)
  const [busy, setBusy] = useState(false)
  const [needsRefresh, setNeedsRefresh] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [editing, setEditing] = useState<User | null>(null)
  const users = useQuery({ queryKey: ['users', after],
    queryFn: ({ signal }) => request('/api/ui/v1/users', 'get', { query: new URLSearchParams(after ? { after } : {}), signal }),
    retry: false, staleTime: 0, gcTime: 0, refetchOnMount: 'always', refetchOnWindowFocus: false, refetchOnReconnect: false })
  const locked = busy || creating || editing !== null
  function clearSecret() { if (secret.current) secret.current.value = '' }
  function close() { if (!busy) { clearSecret(); setReview(null); setCreating(false) } }
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
    clearSecret()
    try {
      const result = await request('/api/ui/v1/users', 'post', { csrf: session.csrf_token, body: { ...review, password } })
      setMessage(`Local user #${result.user_id} created. Refresh the list to review accounts.`)
    } catch (failure) {
      setError(`${failure instanceof Error ? failure.message : 'Creation failed.'} If the response was interrupted, the account may have been created. Refresh and check the user list before another attempt.`)
    } finally {
      setNeedsRefresh(true); setReview(null); setCreating(false); setBusy(false); sending.current = false
    }
  }
  return <section className="page management-page"><div className="page-heading"><div><p className="eyebrow">ACCESS MANAGEMENT</p>
    <h1>Users</h1><p className="muted">Local accounts and directory identities.</p></div>
    <div className="heading-actions">
      <Button variant="secondary" disabled={locked || users.isFetching} onClick={async () => {
        const result = await users.refetch(); if (!result.isError) setNeedsRefresh(false)
      }}><RefreshCw size={14} aria-hidden="true" />Refresh users</Button>
      <Button disabled={locked || needsRefresh} onClick={() => { setMessage(''); setError(''); setCreating(true) }}>
        <Plus size={16} aria-hidden="true" />New local user</Button></div></div>
    {message && <p role="status" className="callout">{message}</p>}
    {error && <p role="alert" className="error">{error}</p>}
    {users.isPending && <p role="status">Loading users…</p>}
    {users.error && <p role="alert" className="error">{users.error.message}</p>}
    {needsRefresh && !users.error && <p className="muted">Refresh users to load current accounts before another change.</p>}
    {!users.error && !needsRefresh && users.data && <>
      <div className="entity-toolbar"><h2>Accounts</h2><p className="muted">{users.data.items.length} on this page ·
        directory roles and passwords are managed by the directory · change your own password in <Link to="/account">Account</Link></p></div>
      {!users.data.items.length && <p className="empty">No users on this page.</p>}
      <ul className="entity-list" aria-label="Users">{users.data.items.map(user => {
        const self = user.id === session.user.id
        const directory = user.auth_source === 'ldap'
        const lastLogin = sinceRecorded(user.last_login_at)
        return <li key={user.id}><button type="button" className="entity-row" disabled={self || locked || users.isFetching}
          aria-label={self ? `${user.username} (you)` : `Manage user #${user.id}`}
          onClick={() => { clearSecret(); setEditing(user) }}>
          <span className={`entity-avatar ${user.role === 'admin' ? 'is-warning' : ''}`} aria-hidden="true">{initials(user)}</span>
          <span className="entity-identity"><strong>{user.username}{user.username_truncated ? '…' : ''}</strong>
            <small>{user.display_name ? `${user.display_name} · ` : ''}#{user.id}</small></span>
          <span className="entity-facts"><span>Last login {lastLogin ? `${lastLogin} ago` : 'never recorded'}</span>
            <span title={user.created_at}>Created {sinceRecorded(user.created_at) ?? '—'} ago</span></span>
          <span className="entity-badges">{self && <span className="tag tag-accent">You</span>}
            <span className={`tag ${user.role === 'admin' ? 'tag-warning' : ''}`}>{user.role === 'admin' ? 'Administrator' : 'Analyst'}</span>
            <span className="tag">{directory ? 'LDAP — directory managed' : 'Local'}</span></span>
          <span className="entity-chevron">{!self && <ChevronRight size={16} aria-hidden="true" />}</span>
        </button></li>
      })}</ul>
      <div className="history-pagination"><Button variant="secondary" disabled={locked || users.isFetching || !after} onClick={() => setParams({})}>First page</Button>
        <Button variant="secondary" disabled={locked || users.isFetching || !users.data.next_after} onClick={() => setParams({ after: String(users.data!.next_after) })}>Next page</Button></div>
    </>}
    <Dialog open={creating} locked={busy} onOpenChange={open => { if (!open) close() }}
      title={review ? 'Create local user?' : 'New local user'}
      description={review ? `Create ${review.username} with ${review.role} access. LDAP users must be managed in the directory.`
        : 'Local accounts sign in with a MASP password. Directory users appear here after their first sign-in.'}>
      {/* The form stays mounted through review so the password is sent only on confirmation, then cleared. */}
      <form onSubmit={prepare} hidden={review !== null} aria-label="Create local user"><fieldset disabled={busy}>
        <label>Username<input name="username" required maxLength={128} autoComplete="off" /></label>
        <label>Role<select name="role" defaultValue="analyst"><option value="analyst">Analyst</option><option value="admin">Administrator</option></select></label>
        <label>Initial password<input ref={secret} type="password" name="password" required minLength={8} maxLength={4096} autoComplete="new-password" /></label>
        <p className="muted">At least 8 characters. The password is cleared on cancellation or submission and is never displayed in the confirmation.</p>
        <div className="report-actions"><Button type="button" variant="secondary" onClick={close}>Cancel</Button><Button type="submit">Review new user</Button></div>
      </fieldset></form>
      {review && <div className="report-actions"><Button variant="secondary" disabled={busy} onClick={close}>Cancel</Button>
        <Button disabled={busy} onClick={() => { void create() }}>{busy ? 'Creating…' : 'Confirm creation'}</Button></div>}
    </Dialog>
    {editing && <UserManagement user={editing} session={session} onClose={() => setEditing(null)} onComplete={(receipt, failure) => {
      setEditing(null); setNeedsRefresh(true); setMessage(receipt); setError(failure)
    }} />}
  </section>
}
