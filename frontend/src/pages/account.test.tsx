import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { expect, it, vi } from 'vitest'
import Account from './account'

function mount({ failure = false, source = 'local' } = {}) {
  const fetcher = vi.fn(async (_url: string, options?: RequestInit) => options?.method === 'POST'
    ? failure ? new Response(JSON.stringify({ detail: 'Unavailable' }), { status: 503 }) : new Response(null, { status: 204 })
    : new Response(JSON.stringify({ user_id: 2, username: 'analyst', role: 'analyst', auth_source: source })))
  vi.stubGlobal('fetch', fetcher)
  const client = new QueryClient()
  const changed = vi.fn()
  render(<QueryClientProvider client={client}><Account onPasswordChanged={changed}
    session={{ user: { id: 2, username: 'analyst', role: 'analyst' }, csrf_token: 'csrf' }} /></QueryClientProvider>)
  return { fetcher, client, changed }
}

async function prepare(confirm = 'new-private-password') {
  await userEvent.type(await screen.findByLabelText('Current password'), 'old-private-password')
  await userEvent.type(screen.getByLabelText('New password', { exact: true }), 'new-private-password')
  await userEvent.type(screen.getByLabelText('Confirm new password'), confirm)
  await userEvent.click(screen.getByRole('button', { name: 'Review password change' }))
}

it('keeps directory passwords outside local management', async () => {
  const { fetcher } = mount({ source: 'ldap' })
  expect(await screen.findByText(/Your password is managed by the directory/)).toBeVisible()
  expect(screen.queryByLabelText('Current password')).toBeNull()
  expect(fetcher).toHaveBeenCalledTimes(1)
})

it('rejects mismatched confirmation without a write and clears all password inputs', async () => {
  const { fetcher } = mount()
  await prepare('mismatched-password')
  expect(screen.getByRole('alert')).toHaveTextContent('must match')
  expect(screen.queryByRole('dialog')).toBeNull()
  expect(document.querySelectorAll('input[type="password"]')).toHaveLength(3)
  for (const input of document.querySelectorAll('input[type="password"]')) expect(input).toHaveValue('')
  expect(fetcher).toHaveBeenCalledTimes(1)
})

it('confirms without exposing passwords and clears inputs when cancelled', async () => {
  const { fetcher } = mount()
  await prepare()
  expect(within(screen.getByRole('dialog')).queryByText(/private-password/)).toBeNull()
  await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
  for (const input of document.querySelectorAll('input[type="password"]')) expect(input).toHaveValue('')
  expect(fetcher).toHaveBeenCalledTimes(1)
})

it.each([false, true])('sends once without caching passwords and checks session after failure (%s)', async failure => {
  const { fetcher, client, changed } = mount({ failure })
  await prepare()
  await userEvent.click(screen.getByRole('button', { name: 'Confirm password change' }))
  if (failure) {
    expect(await screen.findByRole('alert')).toHaveTextContent('password may have changed')
    expect(changed).not.toHaveBeenCalled()
  } else expect(changed).toHaveBeenCalledTimes(1)
  for (const input of document.querySelectorAll('input[type="password"]')) expect(input).toHaveValue('')
  expect(screen.getByRole('button', { name: 'Review password change' })).toBeDisabled()
  expect(fetcher).toHaveBeenCalledTimes(2)
  const write = fetcher.mock.calls.find(([, options]) => options?.method === 'POST')!
  expect(JSON.parse(write[1]!.body as string)).toEqual({ current_password: 'old-private-password', new_password: 'new-private-password', confirm_password: 'new-private-password' })
  expect(new Headers(write[1]!.headers).get('X-CSRF-Token')).toBe('csrf')
  expect(client.getMutationCache().getAll()).toHaveLength(0)
  expect(JSON.stringify(client.getQueryData(['account']))).not.toContain('private-password')
  if (failure) {
    await userEvent.click(screen.getByRole('button', { name: 'Check session' }))
    expect(screen.getByRole('button', { name: 'Review password change' })).not.toBeDisabled()
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1)
  }
})
