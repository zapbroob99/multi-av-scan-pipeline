import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { expect, it, vi } from 'vitest'
import Users from './users'

function mount(failure = false) {
  const fetcher = vi.fn(async (_url: string, options?: RequestInit) => options?.method === 'POST'
    ? new Response(JSON.stringify(failure ? { detail: 'Unavailable' } : { user_id: 8 }), { status: failure ? 503 : 201 })
    : new Response(JSON.stringify({ items: [{ id: 1, username: 'directory-user', username_truncated: false,
      role: 'analyst', auth_source: 'ldap', display_name: '<script>name</script>', created_at: '2026-09-21', last_login_at: null }], next_after: 1 })))
  vi.stubGlobal('fetch', fetcher)
  const client = new QueryClient()
  render(<QueryClientProvider client={client}><MemoryRouter><Users session={{ user: { id: 2, username: 'admin', role: 'admin' }, csrf_token: 'csrf' }} /></MemoryRouter></QueryClientProvider>)
  return { fetcher, client }
}

async function prepare() {
  await userEvent.click(screen.getByRole('button', { name: 'New local user' }))
  await userEvent.type(screen.getByLabelText('Username'), 'new-user')
  await userEvent.type(screen.getByLabelText('Initial password'), 'private-password')
  await userEvent.click(screen.getByRole('button', { name: 'Review new user' }))
}

it('labels directory identities and clears an unsubmitted password on cancellation', async () => {
  const { fetcher } = mount()
  expect(await screen.findByText(/LDAP — directory managed/)).toBeVisible()
  expect(document.querySelector('script')).toBeNull()
  await prepare()
  expect(within(screen.getByRole('dialog')).queryByText('private-password')).toBeNull()
  await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
  expect(screen.queryByRole('dialog')).toBeNull()
  await userEvent.click(screen.getByRole('button', { name: 'New local user' }))
  expect(screen.getByLabelText('Initial password')).toHaveValue('')
  expect(fetcher).toHaveBeenCalledTimes(1)
})

it.each([false, true])('submits once without caching secrets and requires refresh (failure=%s)', async failure => {
  const { fetcher, client } = mount(failure)
  await screen.findByText(/LDAP — directory managed/)
  await prepare()
  await userEvent.click(screen.getByRole('button', { name: 'Confirm creation' }))
  if (failure) expect(await screen.findByRole('alert')).toHaveTextContent('may have been created')
  else expect(await screen.findByRole('status')).toHaveTextContent('Local user #8 created')
  expect(screen.queryByLabelText('Initial password')).toBeNull()
  expect(screen.getByRole('button', { name: 'New local user' })).toBeDisabled()
  expect(fetcher).toHaveBeenCalledTimes(2)
  const write = fetcher.mock.calls.find(([, options]) => options?.method === 'POST')!
  expect(JSON.parse(write[1]!.body as string)).toEqual({ username: 'new-user', role: 'analyst', password: 'private-password' })
  expect(new Headers(write[1]!.headers).get('X-CSRF-Token')).toBe('csrf')
  expect(client.getMutationCache().getAll()).toHaveLength(0)
  expect(JSON.stringify(client.getQueryData(['users', '']))).not.toContain('private-password')
  await userEvent.click(screen.getByRole('button', { name: 'Refresh users' }))
  expect(await screen.findByText(/LDAP — directory managed/)).toBeVisible()
  expect(screen.getByRole('button', { name: 'New local user' })).not.toBeDisabled()
})

it.each(['update', 'delete', 'failure'])('fences managed user %s and requires explicit refresh', async action => {
  const fetcher = vi.fn(async (_url: string, options?: RequestInit) => ['PUT', 'DELETE'].includes(options?.method || '')
    ? action === 'failure' ? new Response(JSON.stringify({ detail: 'Unavailable' }), { status: 503 }) : new Response(null, { status: 204 })
    : new Response(JSON.stringify({ items: [{ id: 8, management_revision: 7, username: 'target', username_truncated: false,
      role: 'analyst', auth_source: 'local', display_name: null, created_at: 'today', last_login_at: null }], next_after: null })))
  vi.stubGlobal('fetch', fetcher)
  const client = new QueryClient()
  render(<QueryClientProvider client={client}><MemoryRouter><Users session={{ user: { id: 2, username: 'admin', role: 'admin' }, csrf_token: 'csrf' }} /></MemoryRouter></QueryClientProvider>)
  await userEvent.click(await screen.findByRole('button', { name: 'Manage user #8' }))
  if (action === 'delete') await userEvent.click(screen.getByRole('button', { name: 'Review removal' }))
  else {
    await userEvent.selectOptions(screen.getByLabelText('Account role'), 'admin')
    await userEvent.type(screen.getByLabelText('Replacement password'), 'private-reset-password')
    await userEvent.click(screen.getByRole('button', { name: 'Review changes' }))
    expect(screen.getByRole('dialog')).not.toHaveTextContent('private-reset-password')
  }
  await userEvent.click(screen.getByRole('button', { name: action === 'delete' ? 'Confirm removal' : 'Confirm changes' }))
  if (action === 'failure') expect(await screen.findByRole('alert')).toHaveTextContent('may have completed')
  else expect(await screen.findByRole('status')).toHaveTextContent(action === 'delete' ? 'removed' : 'updated')
  expect(screen.queryByRole('button', { name: 'Manage user #8' })).toBeNull()
  expect(screen.getByRole('button', { name: 'New local user' })).toBeDisabled()
  const write = fetcher.mock.calls.find(([, options]) => ['PUT', 'DELETE'].includes(options?.method || ''))!
  expect(JSON.parse(write[1]!.body as string)).toEqual(action === 'delete' ? { expected_revision: 7 } : { expected_revision: 7, role: 'admin', password: 'private-reset-password' })
  expect(new Headers(write[1]!.headers).get('X-CSRF-Token')).toBe('csrf')
  expect(client.getMutationCache().getAll()).toHaveLength(0)
  expect(JSON.stringify(client.getQueryData(['users', '']))).not.toContain('private-reset-password')
  await userEvent.click(screen.getByRole('button', { name: 'Refresh users' }))
  expect(await screen.findByRole('button', { name: 'Manage user #8' })).toBeEnabled()
  expect(fetcher.mock.calls.filter(([, options]) => ['PUT', 'DELETE'].includes(options?.method || ''))).toHaveLength(1)
})

it('shows only shadow removal for LDAP users and cancels without writing', async () => {
  const { fetcher } = mount()
  await userEvent.click(await screen.findByRole('button', { name: 'Manage user #1' }))
  expect(screen.queryByLabelText('Replacement password')).toBeNull()
  expect(screen.queryByLabelText('Account role')).toBeNull()
  await userEvent.click(screen.getByRole('button', { name: 'Review removal' }))
  expect(screen.getByRole('dialog')).toHaveTextContent('Directory access is unchanged')
  await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
  expect(fetcher).toHaveBeenCalledTimes(1)
})
