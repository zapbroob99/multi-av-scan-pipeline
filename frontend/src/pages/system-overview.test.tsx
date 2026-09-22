import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import SystemOverview from './system-overview'

function mount() {
  const fetcher = vi.fn(async (url: string) => new Response(JSON.stringify(url.includes('/summary')
    ? { total: 4, queued: 1, running: 1, finalizing: 0, completed: 2, failed: 0,
      registered_nodes: 3, online_nodes: 2, active_online_nodes: 1, retention_days: 30, retention_batch_size: 100,
      generated_at: '2026-09-14T00:00:00Z' }
    : { items: [{ first_result_id: 7, engine_name: '<script>historic</script>', name_truncated: true,
      total: 2, completed: 1, failed: 1, skipped: 0, detections: 1, avg_duration_ms: null, max_duration_ms: null }],
      next_after: 7, generated_at: '2026-09-14T00:00:00Z' })))
  vi.stubGlobal('fetch', fetcher)
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter><SystemOverview /></MemoryRouter></QueryClientProvider>)
  return fetcher
}

describe('System overview', () => {
  it('loads metrics only on demand, renders names as text and preserves the pagination cursor', async () => {
    const fetcher = mount()
    await screen.findByText(/Enabled: 30 days/)
    expect(fetcher).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('link', { name: 'Review retention cleanup' })).toHaveAttribute('href', '/system/retention')
    await userEvent.click(screen.getByRole('button', { name: 'Load engine metrics' }))
    await screen.findByText('<script>historic</script>')
    expect(document.querySelector('script')).toBeNull()
    expect(screen.getByText('Unknown / Unknown')).toBeInTheDocument()
    expect(screen.getByText('Name truncated')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Next engine names' }))
    await waitFor(() => expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/system/engine-metrics?limit=20&after=7', expect.anything()))
  })
  it('hides cached metrics on refresh failure without retrying', async () => {
    const fetcher = mount()
    await userEvent.click(screen.getByRole('button', { name: 'Load engine metrics' }))
    await screen.findByText('<script>historic</script>')
    fetcher.mockImplementation(async () => new Response(JSON.stringify({ detail: 'Unavailable' }), { status: 503 }))
    await userEvent.click(screen.getByRole('button', { name: 'Refresh engine metrics' }))
    await screen.findByRole('alert')
    expect(screen.queryByText('<script>historic</script>')).toBeNull()
    expect(fetcher.mock.calls.filter(([url]) => url.includes('/engine-metrics'))).toHaveLength(2)
  })
})
