import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import ClientProfiles from './client-profiles'

function mount(incomplete = false, fail = false) {
  const fetcher = vi.fn(async (_url: string, options?: RequestInit) => options?.method === 'PUT'
    ? fail ? new Response(JSON.stringify({ detail: 'Routing changed' }), { status: 409 }) : new Response(null, { status: 204 })
    : new Response(JSON.stringify({ client_id: 3, managed: false, next_after: null, engines_incomplete: incomplete,
      items: [{ id: 7, name: '<script>Profile</script>', enabled: true, is_default: true, engine_ids: [1], incomplete: false }],
      engines: [{ id: 1, display_name: 'One', adapter_key: 'static_metadata', enabled: true }, { id: 2, display_name: 'Two', adapter_key: 'clamav', enabled: false }] })))
  vi.stubGlobal('fetch', fetcher)
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter initialEntries={['/service-clients/3/profiles']}><Routes>
    <Route path="/service-clients/:clientId/profiles" element={<ClientProfiles session={{ user: { id: 1, username: 'admin', role: 'admin' }, csrf_token: 'csrf' }} />} />
  </Routes></MemoryRouter></QueryClientProvider>)
  return fetcher
}

describe('Profile routing', () => {
  it('confirms explicit instance IDs and sends the previous selection as a fence', async () => {
    const fetcher = mount()
    await userEvent.click(await screen.findByRole('checkbox', { name: /Two/ }))
    expect(document.querySelector('script')).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Review engine routing' }))
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(fetcher).toHaveBeenCalledTimes(1)
    await userEvent.click(screen.getByRole('button', { name: 'Review engine routing' }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm engine routing' }))
    await screen.findByText('Profile routing saved. Refresh before editing again.')
    const writes = fetcher.mock.calls.filter(([, options]) => options?.method === 'PUT')
    expect(writes).toHaveLength(1)
    expect(writes[0][0]).toBe('/api/ui/v1/service-clients/3/profiles/7/engines')
    expect(JSON.parse(String(writes[0][1]?.body))).toEqual({ engine_ids: [1, 2], expected_engine_ids: [1] })
    expect(writes[0][1]?.headers).toMatchObject({ 'X-CSRF-Token': 'csrf' })
  })
  it('blocks edits from an incomplete engine inventory', async () => {
    mount(true)
    expect(await screen.findByRole('checkbox', { name: /One/ })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Review engine routing' })).toBeDisabled()
  })
  it('requires reconciliation after stale or uncertain writes without replay', async () => {
    const fetcher = mount(false, true)
    await userEvent.click(await screen.findByRole('button', { name: 'Review engine routing' }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm engine routing' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Routing changed')
    expect(screen.queryByRole('checkbox')).toBeNull()
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'PUT')).toHaveLength(1)
  })
})
