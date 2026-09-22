import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import ServiceClients from './service-clients'

function mount(fail = false) {
  const fetcher = vi.fn(async (_url: string, options?: RequestInit) => options?.method === 'PUT'
    ? fail ? new Response(JSON.stringify({ detail: 'Unavailable' }), { status: 503 }) : new Response(null, { status: 204 })
    : new Response(JSON.stringify({ items: [
      { id: 1, client_key: 'legacy-default', display_name: 'Managed', enabled: true, managed: true, metadata_incomplete: false },
      { id: 2, client_key: 'api-one', display_name: '<script>Client</script>', enabled: true, managed: false, metadata_incomplete: false }], next_after: 2 })))
  vi.stubGlobal('fetch', fetcher)
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter><ServiceClients session={{ user: { id: 1, username: 'admin', role: 'admin' }, csrf_token: 'csrf' }} /></MemoryRouter></QueryClientProvider>)
  return fetcher
}

describe('Service clients', () => {
  it('protects managed clients and confirms a scoped state update with CSRF', async () => {
    const fetcher = mount()
    const managed = within(await screen.findByRole('form', { name: 'Edit client 1' }))
    expect(managed.getByRole('button')).toBeDisabled()
    const form = within(screen.getByRole('form', { name: 'Edit client 2' }))
    expect(document.querySelector('script')).toBeNull()
    await userEvent.selectOptions(form.getByLabelText('Client state'), 'disabled')
    await userEvent.click(form.getByRole('button'))
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(fetcher).toHaveBeenCalledTimes(1)
    await userEvent.click(form.getByRole('button'))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm client changes' }))
    await screen.findByText('Service client updated. Refresh clients to see the current state.')
    const writes = fetcher.mock.calls.filter(([, options]) => options?.method === 'PUT')
    expect(writes).toHaveLength(1)
    expect(writes[0][0]).toBe('/api/ui/v1/service-clients/2')
    expect(JSON.parse(String(writes[0][1]?.body))).toEqual({ display_name: '<script>Client</script>', enabled: false })
    expect(writes[0][1]?.headers).toMatchObject({ 'X-CSRF-Token': 'csrf' })
  })
  it('requires refresh after uncertain writes without replay', async () => {
    const fetcher = mount(true)
    const form = within(await screen.findByRole('form', { name: 'Edit client 2' }))
    await userEvent.click(form.getByRole('button'))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm client changes' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('no automatic retry')
    expect(screen.queryByRole('form')).toBeNull()
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'PUT')).toHaveLength(1)
    await userEvent.click(screen.getByRole('button', { name: 'Refresh clients' }))
    await screen.findByRole('form', { name: 'Edit client 2' })
    await userEvent.click(screen.getByRole('button', { name: 'Next clients' }))
    expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/service-clients?limit=20&after=2', expect.anything())
  })
})
