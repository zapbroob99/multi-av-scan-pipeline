import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, expect, it, vi } from 'vitest'
import ConnectionSettings from './connection-settings'

const session = { user: { id: 1, username: 'admin', role: 'admin' as const }, csrf_token: 'csrf' }
function snapshot(provider: string, revision = 'environment') {
  return { provider, revision, source: revision === 'environment' ? 'environment' : 'console',
    enabled: false, has_secret: revision !== 'environment', secret_storage_available: true,
    fields: [{ key: provider === 'ldap' ? 'HOST' : 'MODEL', label: provider === 'ldap' ? 'Directory host' : 'Model ID',
      help: 'Connection field', value: provider === 'ldap' ? 'directory.test' : 'model-one', advanced: false, choices: [] },
      ...(provider === 'ldap' ? [{ key: 'ADMIN_GROUP_DN', label: 'Administrator group DN', value: '' }] : [])] }
}
function mount(failSave = false) {
  const calls: { url: string; init?: RequestInit }[] = []
  let saved = false
  const fetcher = vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init })
    const provider = 'ldap'
    if (init?.method === 'PUT') {
      if (failSave) return new Response(JSON.stringify({ detail: 'Save failed' }), { status: 503 })
      saved = true
      return new Response(JSON.stringify({ saved: true }))
    }
    if (url.endsWith('/ldap/search')) return new Response(JSON.stringify({
      matches: [{ dn: 'CN=team-one,DC=test', name: 'team-one' }], limited: false }))
    if (init?.method === 'POST') return new Response(JSON.stringify({ success: true, message: 'Saved connection verified', role: 'admin' }))
    return new Response(JSON.stringify(snapshot(provider, saved ? 'saved-revision' : 'environment')))
  })
  vi.stubGlobal('fetch', fetcher)
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  const view = render(<QueryClientProvider client={client}><ConnectionSettings session={session} /></QueryClientProvider>)
  return { calls, client, ...view }
}

describe('Connection settings', () => {
  it('searches on demand and fills a role mapping or test username without saving', async () => {
    const { calls } = mount()
    const panel = within(await screen.findByRole('region', { name: 'LDAP settings' }))
    await userEvent.type(await panel.findByLabelText('Group name starts with'), 'team')
    const search = panel.getByRole('button', { name: 'Search directory' })
    expect(calls.filter(call => call.init?.method === 'POST')).toHaveLength(0)
    await userEvent.click(search)
    await userEvent.click(await panel.findByRole('button', { name: 'Use as administrator group' }))
    expect(panel.getByLabelText('Administrator group DN')).toHaveValue('CN=team-one,DC=test')
    await userEvent.selectOptions(panel.getByLabelText('Find'), 'user')
    expect(panel.queryByText('CN=team-one,DC=test')).toBeNull()
    await userEvent.type(panel.getByLabelText('Username starts with'), 'te')
    await userEvent.click(search)
    await userEvent.click(await panel.findByRole('button', { name: 'Use as test username' }))
    expect(panel.getByLabelText('Test username')).toHaveValue('team-one')
    expect(calls.filter(call => call.init?.method === 'PUT')).toHaveLength(0)
    expect(calls.filter(call => call.url.endsWith('/ldap/search')).map(call => JSON.parse(String(call.init?.body)))).toEqual([
      { expected_revision: 'environment', kind: 'group', term: 'team' },
      { expected_revision: 'environment', kind: 'user', term: 'te' }
    ])
  })

  it('confirms one save, protects credentials from caches and reads fresh metadata', async () => {
    const { calls, client } = mount()
    const panel = within(await screen.findByRole('region', { name: 'LDAP settings' }))
    await panel.findByLabelText('Directory host')
    const password = panel.getByLabelText('Search account password')
    await userEvent.type(password, 'hidden-password')
    await userEvent.click(panel.getByRole('button', { name: 'Review LDAP changes' }))
    expect(calls.filter(call => call.init?.method === 'PUT')).toHaveLength(0)
    await userEvent.click(screen.getByRole('button', { name: 'Confirm LDAP changes' }))
    await panel.findByText('Settings saved. New requests use these settings.')
    const writes = calls.filter(call => call.init?.method === 'PUT')
    expect(writes).toHaveLength(1)
    expect(JSON.parse(String(writes[0].init?.body))).toMatchObject({
      expected_revision: 'environment', enabled: false, secret: 'hidden-password', values: { HOST: 'directory.test' },
    })
    expect(writes[0].init?.headers).toMatchObject({ 'X-CSRF-Token': 'csrf' })
    expect(panel.getByLabelText('Search account password')).toHaveValue('')
    expect(JSON.stringify(client.getQueryCache().getAll().map(query => query.state.data))).not.toContain('hidden-password')
    expect(client.getMutationCache().getAll()).toHaveLength(0)
    expect(calls.filter(call => call.url.endsWith('/ldap') && call.init?.method === 'GET')).toHaveLength(2)
  })

  it('releases navigation while a save is pending and requires reload after a lost response', async () => {
    const { calls } = mount()
    const panel = within(await screen.findByRole('region', { name: 'LDAP settings' }))
    await panel.findByLabelText('Directory host')
    let disconnect!: (reason: Error) => void
    vi.mocked(fetch).mockImplementationOnce(() => new Promise((_resolve, reject) => { disconnect = reject }))
    await userEvent.click(panel.getByRole('button', { name: 'Review LDAP changes' }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm LDAP changes' }))
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(panel.getByText('Request in progress…')).toBeVisible()
    disconnect(new TypeError('Failed to fetch'))
    await panel.findByText(/browser could not receive a response/)
    expect(panel.getByRole('button', { name: 'Reload LDAP' })).toBeEnabled()
    await userEvent.click(panel.getByRole('button', { name: 'Reload LDAP' }))
    await panel.findByLabelText('Directory host')
    expect(calls.every(call => call.init?.method === 'GET')).toBe(true)
  })

  it('clears a cancelled secret and blocks another save after an uncertain response', async () => {
    const { calls } = mount(true)
    const panel = within(await screen.findByRole('region', { name: 'LDAP settings' }))
    await panel.findByLabelText('Directory host')
    await userEvent.type(panel.getByLabelText('Search account password'), 'private-key')
    await userEvent.click(panel.getByRole('button', { name: 'Review LDAP changes' }))
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(panel.getByLabelText('Search account password')).toHaveValue('')
    await userEvent.click(panel.getByRole('button', { name: 'Review LDAP changes' }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm LDAP changes' }))
    await panel.findByText(/Reload and check the saved settings/)
    expect(panel.queryByRole('button', { name: 'Review LDAP changes' })).toBeNull()
    expect(calls.filter(call => call.init?.method === 'PUT')).toHaveLength(1)
  })

  it('tests saved LDAP settings with the displayed revision and clears the test password', async () => {
    const { calls, client } = mount()
    const panel = within(await screen.findByRole('region', { name: 'LDAP settings' }))
    await panel.findByLabelText('Test username')
    await userEvent.type(panel.getByLabelText('Test username'), 'operator')
    await userEvent.type(panel.getByLabelText('Test user password'), 'test-password')
    await userEvent.selectOptions(panel.getByLabelText('Expected role'), 'admin')
    await userEvent.click(panel.getByRole('button', { name: 'Test LDAP connection' }))
    await panel.findByText('Saved connection verified')
    expect(panel.getByLabelText('Test user password')).toHaveValue('')
    const tests = calls.filter(call => call.init?.method === 'POST')
    expect(tests).toHaveLength(1)
    expect(JSON.parse(String(tests[0].init?.body))).toEqual({
      expected_revision: 'environment', username: 'operator', password: 'test-password', expected_role: 'admin',
    })
    await waitFor(() => expect(JSON.stringify(client.getQueryCache().getAll().map(query => query.state.data))).not.toContain('test-password'))
  })
})
