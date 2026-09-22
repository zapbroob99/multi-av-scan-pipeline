import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import Runtime from './runtime'

function mount() {
  const fetcher = vi.fn(async (url: string) => new Response(JSON.stringify(url.includes('/workers')
    ? { items: [], next_after: null, stale_after_seconds: 30 }
    : { items: [{ id: 7, filename: '<script>sample</script>', source: 'api', status: 'finalizing', priority: 'High', created_at: '2026-09-14T00:00:00Z' }], next_after: 7 })))
  vi.stubGlobal('fetch', fetcher)
  const client = new QueryClient()
  render(<QueryClientProvider client={client}><MemoryRouter><Runtime /></MemoryRouter></QueryClientProvider>)
  return { fetcher, client }
}

describe('Runtime', () => {
  it('shows automation activity as inert text without linking to a manual report; later pages stop polling', async () => {
    const { fetcher, client } = mount()
    await screen.findByText('<script>sample</script>')
    expect(document.querySelector('script')).toBeNull()
    expect(screen.queryByRole('link', { name: '<script>sample</script>' })).toBeNull()
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
