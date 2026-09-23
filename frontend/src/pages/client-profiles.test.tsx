import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import ClientProfiles from './client-profiles'

function mount(incomplete = false, fail = false, named = false) {
  const fetcher = vi.fn(async (_url: string, options?: RequestInit) => options?.method && options.method !== 'GET'
    ? fail ? new Response(JSON.stringify({ detail: 'Routing changed' }), { status: 409 })
      : options.method === 'POST' ? new Response(JSON.stringify({ profile_id: 8 }), { status: 201 }) : new Response(null, { status: 204 })
    : new Response(JSON.stringify({ client_id: 3, managed: false, next_after: null, engines_incomplete: incomplete,
      default_profile_id: named ? 6 : 7,
      items: [{ id: 7, name: '<script>Profile</script>', enabled: true, is_default: !named, engine_ids: [1], incomplete: false, management_revision: 4 }],
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
    expect(JSON.parse(String(writes[0][1]?.body))).toEqual({ engine_ids: [1, 2], expected_engine_ids: [1], expected_revision: 4 })
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
  it('creates a named profile only after an explicit engine selection and confirmation', async () => {
    const fetcher = mount()
    await userEvent.click(await screen.findByRole('button', { name: 'Add profile' }))
    await userEvent.type(screen.getByLabelText('Profile name'), 'Fast')
    await userEvent.click(screen.getByRole('button', { name: 'Review profile' }))
    expect(screen.getByRole('button', { name: 'Confirm profile change' })).toBeDisabled()
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    await userEvent.click(screen.getAllByRole('checkbox', { name: /One/ })[0])
    await userEvent.click(screen.getByRole('button', { name: 'Review profile' }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm profile change' }))
    await screen.findByText('Profile change saved. Refresh before editing again.')
    const writes = fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')
    expect(writes).toHaveLength(1)
    expect(JSON.parse(String(writes[0][1]?.body))).toEqual({ name: 'Fast', engine_ids: [1] })
    expect(screen.getByRole('button', { name: 'Add profile' })).toBeDisabled()
    await userEvent.click(screen.getByRole('button', { name: 'Refresh profiles' }))
    expect(await screen.findByRole('button', { name: 'Edit profile' })).toBeEnabled()
  })
  it('protects the default profile from disable and delete', async () => {
    mount()
    expect(await screen.findByRole('button', { name: 'Delete profile' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Make default' })).toBeDisabled()
    await userEvent.click(screen.getByRole('button', { name: 'Edit profile' }))
    expect(screen.getByLabelText('Profile state')).toBeDisabled()
  })
  it.each(['default', 'delete'] as const)('confirms a %s operation with the displayed revision', async kind => {
    const fetcher = mount(false, false, true)
    await userEvent.click(await screen.findByRole('button', { name: kind === 'default' ? 'Make default' : 'Delete profile' }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm profile change' }))
    await screen.findByText('Profile change saved. Refresh before editing again.')
    const writes = fetcher.mock.calls.filter(([, options]) => options?.method === (kind === 'default' ? 'PUT' : 'DELETE'))
    expect(writes).toHaveLength(1)
    expect(writes[0][0]).toBe('/api/ui/v1/service-clients/3/profiles/7' + (kind === 'default' ? '/default' : ''))
    expect(JSON.parse(String(writes[0][1]?.body))).toEqual(kind === 'default'
      ? { expected_revision: 4, expected_default_profile_id: 6 } : { expected_revision: 4 })
  })
  it('renames and disables a named profile with its revision', async () => {
    const fetcher = mount(false, false, true)
    await userEvent.click(await screen.findByRole('button', { name: 'Edit profile' }))
    await userEvent.clear(screen.getByLabelText('Profile name'))
    await userEvent.type(screen.getByLabelText('Profile name'), 'Renamed')
    await userEvent.selectOptions(screen.getByLabelText('Profile state'), 'disabled')
    await userEvent.click(screen.getByRole('button', { name: 'Review profile' }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm profile change' }))
    await screen.findByText('Profile change saved. Refresh before editing again.')
    const writes = fetcher.mock.calls.filter(([, options]) => options?.method === 'PUT')
    expect(JSON.parse(String(writes[0][1]?.body))).toEqual({ name: 'Renamed', enabled: false, expected_revision: 4 })
  })
})
