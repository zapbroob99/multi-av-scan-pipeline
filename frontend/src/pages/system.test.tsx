import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import System from './system'

function mount() {
  const worker = { node_id: 'node-a', display_name: '<script>worker</script>', hostname: 'host', platform: 'windows',
    agent_version: '1', capacity: 2, lifecycle_state: 'active', runtime_state: 'idle', active_scan_id: null,
    last_heartbeat_at: 1, age_seconds: 60, online: false, labels: {}, engine_keys: ['microsoft_defender'], metadata_incomplete: false }
  const fetcher = vi.fn(async (_url: string, options?: RequestInit) => new Response(JSON.stringify(
    options?.method === 'POST' ? { node_id: 'node-a', revoked_count: 1 }
      : { items: [worker], next_after: 'node-a', stale_after_seconds: 30 })))
  vi.stubGlobal('fetch', fetcher)
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  render(<QueryClientProvider client={client}><MemoryRouter><System session={{
    user: { id: 1, username: 'admin', role: 'admin' }, csrf_token: 'csrf',
  }} /></MemoryRouter></QueryClientProvider>)
  return { fetcher }
}

describe('System worker management', () => {
  it('renders inert worker identity and confirms an explicit lifecycle with CSRF', async () => {
    const { fetcher } = mount()
    await screen.findByRole('heading', { name: '<script>worker</script>' })
    expect(document.querySelector('script')).toBeNull()
    expect(screen.getByText('Offline')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Apply lifecycle' })).toBeDisabled()
    await userEvent.selectOptions(screen.getByLabelText('Lifecycle for node-a'), 'draining')
    await userEvent.click(screen.getByRole('button', { name: 'Apply lifecycle' }))
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0)
    await userEvent.click(screen.getByRole('button', { name: 'Confirm worker action' }))
    await screen.findByText('Lifecycle for node-a changed to draining.')
    const writes = fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')
    expect(writes).toHaveLength(1)
    expect(writes[0][0]).toBe('/api/ui/v1/system/workers/lifecycle')
    expect(JSON.parse(String(writes[0][1]?.body))).toEqual({ node_id: 'node-a', lifecycle_state: 'draining' })
    expect(writes[0][1]?.headers).toMatchObject({ 'X-CSRF-Token': 'csrf' })
  })
  it('allows cancelling credential revocation and requires a separate confirmation', async () => {
    const { fetcher } = mount()
    await userEvent.click(await screen.findByRole('button', { name: 'Revoke agent credentials' }))
    expect(screen.getByRole('dialog')).toHaveTextContent('Running Control API work loses authorization')
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0)
    await userEvent.click(screen.getByRole('button', { name: 'Revoke agent credentials' }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm worker action' }))
    await screen.findByText(/Revoked 1 agent credential/)
    const writes = fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')
    expect(writes).toHaveLength(1)
    expect(writes[0][0]).toBe('/api/ui/v1/system/workers/credentials/revoke')
    expect(JSON.parse(String(writes[0][1]?.body))).toEqual({ node_id: 'node-a' })
  })
  it('does not replay uncertain writes and hides stale controls when refresh fails', async () => {
    const { fetcher } = mount()
    await userEvent.click(await screen.findByRole('button', { name: 'Revoke agent credentials' }))
    fetcher.mockImplementation(async () => new Response(JSON.stringify({ detail: 'Unavailable' }), { status: 503 }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm worker action' }))
    await screen.findByText(/request may have reached the server/)
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Revoke agent credentials' })).toBeNull())
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1)
  })
  it('uses the returned keyset cursor for the next page', async () => {
    const { fetcher } = mount()
    await userEvent.click(await screen.findByRole('button', { name: 'Next workers' }))
    await waitFor(() => expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/system/workers?limit=20&after=node-a', expect.anything()))
    await userEvent.click(screen.getByRole('button', { name: 'First workers' }))
    await waitFor(() => expect(fetcher.mock.calls.at(-1)?.[0]).toBe('/api/ui/v1/system/workers?limit=20'))
  })
})
