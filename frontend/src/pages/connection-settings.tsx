import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useQuery } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import type { components } from '../lib/api.generated'
import { Button } from '../components/ui/button'
import { Dialog } from '../components/ui/dialog'
import { ErrorMessage } from '../components/error-message'

type Field = components['schemas']['ConnectionField']
type Provider = 'ldap'

async function waitForResponse<T>(operation: (signal: AbortSignal) => Promise<T>, milliseconds: number, parent?: AbortSignal) {
  const controller = new AbortController()
  const stop = () => controller.abort()
  parent?.addEventListener('abort', stop, { once: true })
  if (parent?.aborted) stop()
  const timer = window.setTimeout(stop, milliseconds)
  try {
    return await operation(controller.signal)
  } catch (failure) {
    if (controller.signal.aborted && !parent?.aborted) {
      throw new Error('MASP did not respond before the waiting time expired. Check the console connection.')
    }
    if (failure instanceof TypeError) {
      throw new Error('The browser could not receive a response from MASP. Check your console connection and any SSH tunnel.')
    }
    throw failure
  } finally {
    window.clearTimeout(timer)
    parent?.removeEventListener('abort', stop)
  }
}

type DirectoryTarget = 'ADMIN_GROUP_DN' | 'ANALYST_GROUP_DN' | 'username'

function DirectorySearch({ revision, session, disabled, select }: {
  revision: string; session: Session; disabled: boolean; select: (field: DirectoryTarget, value: string) => void
}) {
  const [kind, setKind] = useState<'group' | 'user'>('group')
  const [term, setTerm] = useState('')
  const [result, setResult] = useState<components['schemas']['DirectoryMatches'] | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const active = useRef<AbortController | null>(null)
  useEffect(() => () => active.current?.abort(), [])
  function reset() { setResult(null); setError('') }
  async function search(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (disabled || active.current || term.trim().length < 2) return
    const controller = new AbortController()
    active.current = controller
    reset(); setLoading(true)
    try {
      const rows = await waitForResponse(signal => request('/api/ui/v1/administration/connections/ldap/search', 'post', {
        body: { expected_revision: revision, term: term.trim(), kind }, csrf: session.csrf_token, signal
      }), 60000, controller.signal)
      if (!controller.signal.aborted) setResult(rows)
    } catch (failure) {
      if (!controller.signal.aborted) setError((failure as Error).message)
    } finally { active.current = null; setLoading(false) }
  }
  return <form aria-label="Search directory" onSubmit={search} autoComplete="off">
    <fieldset disabled={disabled || loading}><h3>Search directory</h3>
      <p>Search the saved base for a group or a test user. Save connection changes before searching.</p>
      <label>Find<select value={kind} onChange={event => { setKind(event.target.value as typeof kind); setTerm(''); reset() }}>
        <option value="group">Groups</option><option value="user">Users</option></select></label>
      <label>{kind === 'group' ? 'Group name starts with' : 'Username starts with'}
        <input value={term} minLength={2} maxLength={100} onChange={event => { setTerm(event.target.value); reset() }} /></label>
      <Button type="submit" variant="secondary" disabled={term.trim().length < 2}>Search directory</Button>
      {result && <>
        {result.limited && <p role="status">Results are limited. Enter a longer prefix.</p>}
        {!result.matches.length && !result.limited && <p role="status">No matches in the saved search base.</p>}
        <ul>{result.matches.map(row => <li key={row.dn}><strong>{row.name}</strong><p>{row.dn}</p>
          {kind === 'group' ? <>
            <Button type="button" variant="secondary" onClick={() => select('ADMIN_GROUP_DN', row.dn)}>Use as administrator group</Button>
            <Button type="button" variant="secondary" onClick={() => select('ANALYST_GROUP_DN', row.dn)}>Use as analyst group</Button>
          </> : <Button type="button" variant="secondary" onClick={() => select('username', row.name)}>Use as test username</Button>}
        </li>)}</ul></>}
    </fieldset>
    {loading && <p role="status">Searching directory…</p>}
    {error && <p role="alert"><ErrorMessage message={error} /></p>}
  </form>
}

function ConnectionEditor({ provider, session }: { provider: Provider; session: Session }) {
  const title = 'LDAP'
  const formRef = useRef<HTMLFormElement>(null)
  const secretRef = useRef<HTMLInputElement>(null)
  const testPassword = useRef<HTMLInputElement>(null)
  const testUsername = useRef<HTMLInputElement>(null)
  const sending = useRef(false)
  const active = useRef<AbortController | null>(null)
  useEffect(() => () => active.current?.abort(), [])
  const [review, setReview] = useState(false)
  const [busy, setBusy] = useState(false)
  const [needsRefresh, setNeedsRefresh] = useState(false)
  const [version, setVersion] = useState(0)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const snapshot = useQuery({ queryKey: ['connection-settings', provider], gcTime: 0, retry: false,
    networkMode: 'always',
    queryFn: ({ signal }) => waitForResponse(scoped => request('/api/ui/v1/administration/connections/{provider}', 'get',
      { params: { provider }, signal: scoped }), 15000, signal),
    refetchOnWindowFocus: false, refetchOnReconnect: false, refetchOnMount: 'always' })
  const data = snapshot.data

  function value(name: string) {
    return (formRef.current?.elements.namedItem(name) as HTMLInputElement | null)?.value || ''
  }
  function clearSecrets() {
    if (secretRef.current) secretRef.current.value = ''
    if (testPassword.current) testPassword.current.value = ''
  }
  async function reload() {
    clearSecrets()
    setError(''); setNotice('')
    const result = await snapshot.refetch()
    if (!result.error) { setNeedsRefresh(false); setVersion(previous => previous + 1) }
  }
  async function save() {
    if (!data || sending.current) return
    sending.current = true
    const body = { expected_revision: data.revision, enabled: value('enabled') === '1',
      values: Object.fromEntries(data.fields.map(field => [field.key, value(field.key)])),
      secret: secretRef.current?.value || null }
    clearSecrets()
    setReview(false)
    const controller = new AbortController()
    active.current = controller
    setBusy(true); setError(''); setNotice('')
    try {
      await waitForResponse(signal => request('/api/ui/v1/administration/connections/{provider}', 'put', {
        params: { provider }, csrf: session.csrf_token, body, signal }), 15000, controller.signal)
      setNeedsRefresh(true)
      const result = await snapshot.refetch()
      if (!result.error) {
        setVersion(previous => previous + 1)
        setNeedsRefresh(false)
        setNotice('Settings saved. New requests use these settings.')
      }
    } catch (failure) {
      setError((failure as Error).message)
      setNeedsRefresh(true)
    } finally { active.current = null; sending.current = false; setBusy(false) }
  }
  async function test(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!data || sending.current) return
    sending.current = true
    const form = new FormData(event.currentTarget)
    const body = { expected_revision: data.revision, username: String(form.get('username') || ''),
      password: testPassword.current?.value || null,
      expected_role: String(form.get('expected_role')) as 'admin' | 'analyst' }
    clearSecrets()
    const controller = new AbortController()
    active.current = controller
    setBusy(true); setError(''); setNotice('')
    try {
      const result = await waitForResponse(signal => request('/api/ui/v1/administration/connections/{provider}/test', 'post', {
        params: { provider }, csrf: session.csrf_token, body, signal }), 60000, controller.signal)
      setNotice(result.message)
    } catch (failure) { setError((failure as Error).message) }
    finally { active.current = null; sending.current = false; setBusy(false) }
  }
  function control(field: Field) {
    const id = provider + '-' + field.key
    const choices = field.choices ?? []
    return <div className="setting-row" key={field.key}><div className="setting-label">
      <label htmlFor={id}>{field.label}</label><p id={id + '-help'}>{field.help}</p></div>
      <div className="setting-control">{choices.length
        ? <select id={id} name={field.key} defaultValue={field.value} aria-describedby={id + '-help'}>
          {!choices.includes(field.value ?? '') && <option value={field.value}>Current value ({field.value})</option>}
          {choices.map(choice => <option key={choice}>{choice}</option>)}</select>
        : field.key === 'CA_PEM'
          ? <textarea id={id} name={field.key} rows={5} defaultValue={field.value} maxLength={64000} aria-describedby={id + '-help'} />
          : <input id={id} name={field.key} defaultValue={field.value} maxLength={2048} aria-describedby={id + '-help'} />}
      </div></div>
  }
  const disabled = busy || review || snapshot.isFetching
  return <section className="settings-workspace-section" aria-label={title + ' settings'}>
    <div className="page-heading"><h2>{title}</h2><Button variant="secondary" disabled={disabled}
      onClick={() => { void reload() }}>Reload {title}</Button></div>
    {snapshot.isPending && <p role="status">Loading settings…</p>}
    {snapshot.error && <p role="alert" className="error"><ErrorMessage message={snapshot.error.message} /></p>}
    {error && <p role="alert" className="error"><ErrorMessage message={error} /></p>}
    {notice && <p role="status" className="callout">{notice}</p>}
    {needsRefresh && <p className="callout">Reload and check the saved settings before another change. The previous request may have completed.</p>}
    {data && !snapshot.error && !needsRefresh && <>
      <p className="muted">Source · {data.source === 'console' ? 'Saved in MASP' : 'Server configuration'}.
        Changes apply to subsequent directory sign-ins. Keep a working local administrator account.</p>
      {!data.secret_storage_available && <p className="callout">The server needs a valid MASP_SECRET_ENCRYPTION_KEY to store a new credential.</p>}
      {data.deployment_ca_file && <p className="callout">A deployment-managed LDAP CA file also applies to this connection.</p>}
      <form key={version} ref={formRef} className="settings-panel" autoComplete="off"
        onSubmit={event => { event.preventDefault(); setError(''); setNotice(''); setReview(true) }}>
        <fieldset disabled={disabled}><div className="settings-panel-body">
          <div className="setting-row"><div className="setting-label"><label htmlFor={provider + '-enabled'}>Enable {title}</label></div>
            <div className="setting-control"><select id={provider + '-enabled'} name="enabled" defaultValue={data.enabled ? '1' : '0'}>
              <option value="0">Off</option><option value="1">On</option></select></div></div>
          {data.fields.filter(field => !field.advanced).map(control)}
          <div className="setting-row"><div className="setting-label"><label htmlFor={provider + '-secret'}>
            Search account password</label>
            <p id={provider + '-secret-help'}>{data.has_secret ? 'A credential is configured. Leave blank to keep it.' : 'Enter the credential for this connection.'}</p></div>
            <div className="setting-control"><input ref={secretRef} id={provider + '-secret'} type="password" maxLength={4096}
              autoComplete="new-password" aria-describedby={provider + '-secret-help'} /></div></div>
          <details><summary>Advanced settings and certificates</summary>{data.fields.filter(field => field.advanced).map(control)}</details>
        </div><div className="settings-panel-footer"><p>{!data.enabled
          ? 'For first setup, save with LDAP off. Test a directory user below, then enable LDAP after the expected role is verified.'
          : 'Save your changes before testing the connection.'}</p>
          <Button type="submit">Review {title} changes</Button></div></fieldset>
      </form>
      <DirectorySearch key={data.revision + '-' + version} revision={data.revision}
        session={session} disabled={disabled} select={(field, selected) => {
          if (field === 'username' && testUsername.current) {
            testUsername.current.value = selected
            if (testPassword.current) { testPassword.current.value = ''; testPassword.current.focus() }
          } else {
            const input = formRef.current?.elements.namedItem(field)
            if (input instanceof HTMLInputElement) {
              input.value = selected
              input.focus()
              setNotice('Group selected. Review LDAP changes to save the role mapping.')
            }
          }
        }} />
      <form aria-label={'Test ' + title} onSubmit={test} autoComplete="off">
        <fieldset disabled={disabled}><h3>Test saved {title} settings</h3>
          <label>Test username<input ref={testUsername} name="username" maxLength={255} required aria-describedby="test-username-help" /></label>
            <p id="test-username-help">With sAMAccountName, enter the short account name without the domain.</p>
            <label>Test user password<input ref={testPassword} type="password" maxLength={4096} autoComplete="new-password" required /></label>
            <label>Expected role<select name="expected_role"><option value="analyst">Analyst</option><option value="admin">Administrator</option></select></label>
          <Button type="submit" variant="secondary">Test {title} connection</Button>
        </fieldset>
      </form>
    </>}
    {busy && <p role="status">Request in progress…</p>}
    <Dialog open={review} locked={busy} onOpenChange={open => { if (!busy) { setReview(open); if (!open) clearSecrets() } }}
      title={'Confirm ' + title + ' changes'} description="The saved settings take effect for subsequent requests.">
      <p>Save the edited {title} connection and enabled state?</p>
      <p>Directory users receive the roles mapped by the selected groups on their next sign-in.</p>
      <div className="report-actions"><Button variant="secondary" disabled={busy} onClick={() => { clearSecrets(); setReview(false) }}>Cancel</Button>
        <Button disabled={busy} onClick={() => { void save() }}>Confirm {title} changes</Button></div>
    </Dialog>
  </section>
}

export default function ConnectionSettings({ session }: { session: Session }) {
  return <section className="page management-page"><div className="page-heading"><div><h1>Directory sign-in</h1>
    <p className="muted">Manage LDAP sign-in, trusted certificates and role groups.</p></div></div>
    <ConnectionEditor provider="ldap" session={session} />
  </section>
}
