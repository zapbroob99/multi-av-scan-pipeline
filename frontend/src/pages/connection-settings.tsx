import { useRef, useState, type FormEvent } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import type { components } from '../lib/api.generated'
import { Button } from '../components/ui/button'
import { Dialog } from '../components/ui/dialog'
import { ErrorMessage } from '../components/error-message'

type Field = components['schemas']['ConnectionField']
type Provider = 'ldap' | 'aselix'

function ConnectionEditor({ provider, session }: { provider: Provider; session: Session }) {
  const title = provider === 'ldap' ? 'LDAP' : 'Aselix AI'
  const client = useQueryClient()
  const formRef = useRef<HTMLFormElement>(null)
  const secretRef = useRef<HTMLInputElement>(null)
  const testPassword = useRef<HTMLInputElement>(null)
  const sending = useRef(false)
  const [review, setReview] = useState(false)
  const [busy, setBusy] = useState(false)
  const [needsRefresh, setNeedsRefresh] = useState(false)
  const [version, setVersion] = useState(0)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const snapshot = useQuery({ queryKey: ['connection-settings', provider], gcTime: 0, retry: false,
    queryFn: ({ signal }) => request('/api/ui/v1/administration/connections/{provider}', 'get', { params: { provider }, signal }),
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
    setBusy(true); setError(''); setNotice('')
    try {
      await request('/api/ui/v1/administration/connections/{provider}', 'put', {
        params: { provider }, csrf: session.csrf_token, body })
      setNeedsRefresh(true)
      const result = await snapshot.refetch()
      if (!result.error) {
        setVersion(previous => previous + 1)
        setNeedsRefresh(false)
        setNotice('Settings saved. New requests use these settings.')
      }
      await client.invalidateQueries({ queryKey: ['session'] })
    } catch (failure) {
      setError((failure as Error).message)
      setNeedsRefresh(true)
    } finally { sending.current = false; setBusy(false); setReview(false) }
  }
  async function test(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!data || sending.current) return
    sending.current = true
    const form = new FormData(event.currentTarget)
    const body = { expected_revision: data.revision, username: String(form.get('username') || ''),
      password: testPassword.current?.value || null,
      expected_role: provider === 'ldap' ? String(form.get('expected_role')) as 'admin' | 'analyst' : null }
    clearSecrets()
    setBusy(true); setError(''); setNotice('')
    try {
      const result = await request('/api/ui/v1/administration/connections/{provider}/test', 'post', {
        params: { provider }, csrf: session.csrf_token, body })
      setNotice(result.message)
    } catch (failure) { setError((failure as Error).message) }
    finally { sending.current = false; setBusy(false) }
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
        {provider === 'ldap' ? ' Changes apply to subsequent directory sign-ins. Keep a working local administrator account.' : ' Changes apply to subsequent AI requests.'}</p>
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
            {provider === 'ldap' ? 'Search account password' : 'API key'}</label>
            <p id={provider + '-secret-help'}>{data.has_secret ? 'A credential is configured. Leave blank to keep it.' : 'Enter the credential for this connection.'}</p></div>
            <div className="setting-control"><input ref={secretRef} id={provider + '-secret'} type="password" maxLength={4096}
              autoComplete="new-password" aria-describedby={provider + '-secret-help'} /></div></div>
          <details><summary>Advanced settings and certificates</summary>{data.fields.filter(field => field.advanced).map(control)}</details>
        </div><div className="settings-panel-footer"><p>Save once, then test the saved connection.</p>
          <Button type="submit">Review {title} changes</Button></div></fieldset>
      </form>
      <form aria-label={'Test ' + title} onSubmit={test} autoComplete="off">
        <fieldset disabled={disabled}><h3>Test saved {title} settings</h3>
          {provider === 'ldap' ? <><label>Test username<input name="username" maxLength={255} required /></label>
            <label>Test user password<input ref={testPassword} type="password" maxLength={4096} autoComplete="new-password" required /></label>
            <label>Expected role<select name="expected_role"><option value="analyst">Analyst</option><option value="admin">Administrator</option></select></label></>
            : <p className="muted">Sends a short test question to your saved Aselix endpoint.</p>}
          <Button type="submit" variant="secondary">Test {title} connection</Button>
        </fieldset>
      </form>
    </>}
    {busy && <p role="status">Request in progress…</p>}
    <Dialog open={review} locked={busy} onOpenChange={open => { if (!busy) { setReview(open); if (!open) clearSecrets() } }}
      title={'Confirm ' + title + ' changes'} description="The saved settings take effect for subsequent requests.">
      <p>Save the edited {title} connection and enabled state?</p>
      {provider === 'ldap' && <p>Directory users receive the roles mapped by the selected groups on their next sign-in.</p>}
      <div className="report-actions"><Button variant="secondary" disabled={busy} onClick={() => { clearSecrets(); setReview(false) }}>Cancel</Button>
        <Button disabled={busy} onClick={() => { void save() }}>Confirm {title} changes</Button></div>
    </Dialog>
  </section>
}

export default function ConnectionSettings({ session }: { session: Session }) {
  return <section className="page management-page"><div className="page-heading"><div><h1>LDAP & AI</h1>
    <p className="muted">Manage directory sign-in and your internal Aselix assistant. Credentials are stored encrypted.</p></div></div>
    <ConnectionEditor provider="ldap" session={session} /><ConnectionEditor provider="aselix" session={session} />
  </section>
}
