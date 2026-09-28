import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import Runtime from './runtime'

function mount(source = 'api', initialEntry = '/') {
  const fetcher = vi.fn(async (url: string) => new Response(JSON.stringify(url.includes('/workers')
    ? { items: [{ node_id: 'node/a', display_name: 'Worker A', online: false, lifecycle_state: 'active',
      last_heartbeat_at: 0, age_seconds: 1790580124, runtime_state: 'idle', active_scan_id: 7 }], next_after: null, stale_after_seconds: 30 }
    : { items: [{ id: 7, filename: '<script>sample</script>', source, status: 'finalizing', priority: 'High', created_at: '2026-09-14T00:00:00Z' }], next_after: 7 })))
  vi.stubGlobal('fetch', fetcher)
  const client = new QueryClient()
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[initialEntry]}><Runtime /></MemoryRouter></QueryClientProvider>)
  return { fetcher, client }
}

describe('Runtime', () => {
  it.each(['api', 'icap', 'manual'])('preserves %s source and bounded worker page context in investigation links', async source => {
    mount(source, '/system/runtime?worker_after=earlier')
    expect(await screen.findByRole('link', { name: '<script>sample</script>' })).toHaveAttribute('href',
      source === 'manual' ? '/scans/7' : '/api-ledger/scans/7')
    expect(screen.getByRole('link', { name: 'Worker A' })).toHaveAttribute('href', '/system?node=node%2Fa&after=earlier')
    expect(screen.getByRole('link', { name: 'Scan #7' })).toHaveAttribute('href', '/scans/7')
    expect(screen.getByText('No heartbeat recorded')).toBeVisible()
  })
  it('links inert automation names to automation reports; later pages stop polling', async () => {
    const { fetcher, client } = mount()
    await screen.findByText('<script>sample</script>')
    expect(document.querySelector('script')).toBeNull()
    expect(screen.getByRole('link', { name: '<script>sample</script>' })).toHaveAttribute('href', '/api-ledger/scans/7')
    await userEvent.click(screen.getByRole('button', { name: 'Next scans' }))
    await waitFor(() => expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/system/queue?limit=20&after=7', expect.anything()))
    const query = client.getQueryCache().find({ queryKey: ['system-queue', '7'] })
    expect(query?.options).toMatchObject({ refetchInterval: false })
  })
  it('removes stale queue rows when a refresh fails without automatic retries', async () => {
    const { fetcher } = mount()
    await screen.findByText('<script>sample</script>')
    fetcher.mockImplementation(async () => new Response(JSON.stringify({ detail: 'Unavailable' }), { status: 503 }))
    await userEvent.click(screen.getByRole('button', { name: 'Refresh runtime' }))
    await waitFor(() => expect(screen.queryByText('<script>sample</script>')).toBeNull())
    expect(fetcher.mock.calls.filter(([url]) => url.includes('/queue'))).toHaveLength(2)
  })
})
