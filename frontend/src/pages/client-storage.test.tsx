import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import ClientStorage from './client-storage'

function mount({ fail = false, managed = false, readError = false } = {}) {
  const fetcher = vi.fn(async (_url: string, options?: RequestInit) => options?.method === 'PUT'
    ? fail ? new Response(JSON.stringify({ detail: 'Storage access changed' }), { status: 409 }) : new Response(null, { status: 204 })
    : readError ? new Response(JSON.stringify({ detail: 'Storage configuration unavailable' }), { status: 503 })
      : new Response(JSON.stringify({ client_id: 3, managed, mode: 'environment', revision: 2, environment_fingerprint: 'a'.repeat(64),
        backends: ['archive', 'shared'], grants: [{ backend_key: 'shared', access: 'prefixes', prefixes: ['incoming/client-a/'] }],
        environment_grants: [{ backend_key: 'shared', access: 'prefixes', prefixes: ['incoming/client-a/'] }] })))
  vi.stubGlobal('fetch', fetcher)
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter initialEntries={['/service-clients/3/storage']}><Routes>
    <Route path="/service-clients/:clientId/storage" element={<ClientStorage session={{ user: { id: 1, username: 'admin', role: 'admin' }, csrf_token: 'csrf' }} />} />
  </Routes></MemoryRouter></QueryClientProvider>)
  return fetcher
}

describe('Client storage access', () => {
  it('confirms prefix replacement with revision and environment fences', async () => {
    const fetcher = mount()
    await userEvent.selectOptions(await screen.findByLabelText('Access source'), 'custom')
    await userEvent.clear(screen.getByLabelText(/Allowed prefixes for shared/))
    await userEvent.type(screen.getByLabelText(/Allowed prefixes for shared/), 'incoming/new-client/\narchive/client-a/')
    await userEvent.click(screen.getByRole('button', { name: 'Review storage access' }))
    const confirmation = screen.getByRole('dialog')
    expect(within(confirmation).getByText(/incoming\/new-client/)).toBeVisible()
    await userEvent.click(within(confirmation).getByRole('button', { name: 'Cancel' }))
    expect(fetcher).toHaveBeenCalledTimes(1)
    await userEvent.click(screen.getByRole('button', { name: 'Review storage access' }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm storage access' }))
    await screen.findByText('Storage access saved. Refresh before editing again.')
    const writes = fetcher.mock.calls.filter(([, options]) => options?.method === 'PUT')
    expect(writes).toHaveLength(1)
    expect(writes[0][0]).toBe('/api/ui/v1/service-clients/3/storage')
    expect(JSON.parse(String(writes[0][1]?.body))).toEqual({ mode: 'custom', expected_revision: 2,
      expected_environment_fingerprint: 'a'.repeat(64), grants: [{ backend_key: 'shared', access: 'prefixes', prefixes: ['incoming/new-client/', 'archive/client-a/'] }] })
    expect(writes[0][1]?.headers).toMatchObject({ 'X-CSRF-Token': 'csrf' })
    expect(screen.queryByLabelText('Access source')).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Refresh storage access' }))
    expect(await screen.findByLabelText('Access source')).toBeEnabled()
  })
  it('represents an explicit deny-all with an empty custom list', async () => {
    const fetcher = mount()
    await userEvent.selectOptions(await screen.findByLabelText('Access source'), 'custom')
    await userEvent.selectOptions(screen.getByLabelText('Access for shared'), 'none')
    await userEvent.click(screen.getByRole('button', { name: 'Review storage access' }))
    expect(within(screen.getByRole('dialog')).getByText('No backend access is granted.')).toBeVisible()
    await userEvent.click(screen.getByRole('button', { name: 'Confirm storage access' }))
    await screen.findByText('Storage access saved. Refresh before editing again.')
    const write = fetcher.mock.calls.find(([, options]) => options?.method === 'PUT')!
    expect(JSON.parse(String(write[1]?.body))).toMatchObject({ mode: 'custom', grants: [] })
  })
  it('previews environment grants on reset and sends no custom grants', async () => {
    const fetcher = mount()
    await userEvent.click(await screen.findByRole('button', { name: 'Review storage access' }))
    expect(within(screen.getByRole('dialog')).getByText('incoming/client-a/')).toBeVisible()
    await userEvent.click(screen.getByRole('button', { name: 'Confirm storage access' }))
    await screen.findByText('Storage access saved. Refresh before editing again.')
    const write = fetcher.mock.calls.find(([, options]) => options?.method === 'PUT')!
    expect(JSON.parse(String(write[1]?.body))).toMatchObject({ mode: 'environment', grants: [] })
  })
  it('requires explicit refresh after a stale write, without replay', async () => {
    const fetcher = mount({ fail: true })
    await userEvent.click(await screen.findByRole('button', { name: 'Review storage access' }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm storage access' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Storage access changed')
    expect(screen.queryByRole('button', { name: 'Review storage access' })).toBeNull()
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'PUT')).toHaveLength(1)
  })
  it('keeps compatibility clients read-only', async () => {
    mount({ managed: true })
    expect(await screen.findByLabelText('Access source')).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Review storage access' })).toBeDisabled()
  })
  it('does not present a fallback editor when the read fails', async () => {
    mount({ readError: true })
    expect(await screen.findByRole('alert')).toHaveTextContent('Storage configuration unavailable')
    expect(screen.queryByLabelText('Access source')).toBeNull()
  })
})
