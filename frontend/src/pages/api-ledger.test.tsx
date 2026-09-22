import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import ApiLedger from './api-ledger'

function mount() {
  const fetcher = vi.fn(async (_url: string) => new Response(JSON.stringify({ items: [{ id: 42, filename: '<script>API sample</script>',
    sha256: 'a'.repeat(64), size_bytes: 1024, case_name: 'Case', source: 'icap', service_client_id: 7,
    client_name: 'Integration', batch_id: 3, status: 'completed', risk_score: 0, risk_level: 'info', created_at: '2026-09-17' }], next_before: 42 })))
  vi.stubGlobal('fetch', fetcher)
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter><ApiLedger /></MemoryRouter></QueryClientProvider>)
  return fetcher
}

describe('API ledger', () => {
  it('renders inert previews with honest risk labels and compatible report links', async () => {
    mount()
    await screen.findByRole('heading', { name: '<script>API sample</script>' })
    expect(document.querySelector('script')).toBeNull()
    expect(screen.getByText(/Recorded risk is not a clean verdict/)).toBeVisible()
    expect(screen.getByRole('link', { name: 'Open report' })).toHaveAttribute('href', '/api-ledger/scans/42')
    expect(screen.getByRole('link', { name: 'Open batch' })).toHaveAttribute('href', '/api-ledger/batches/3')
  })
  it('preserves scoped filters across seek pages and supports unassigned ownership', async () => {
    const fetcher = mount()
    await screen.findByRole('heading', { name: '<script>API sample</script>' })
    await userEvent.click(screen.getByRole('button', { name: 'Filter client #7' }))
    expect(fetcher.mock.lastCall?.[0]).toBe('/api/ui/v1/api-ledger?client_id=7&limit=20')
    await userEvent.click(screen.getByRole('button', { name: 'Older scans' }))
    expect(fetcher.mock.lastCall?.[0]).toBe('/api/ui/v1/api-ledger?client_id=7&before=42&limit=20')
    await userEvent.click(screen.getByRole('checkbox'))
    await userEvent.click(screen.getByRole('button', { name: 'Apply filters' }))
    expect(fetcher.mock.lastCall?.[0]).toBe('/api/ui/v1/api-ledger?unassigned=true&limit=20')
  })
  it('hides cached history after a failed refresh without retry', async () => {
    const fetcher = mount()
    await screen.findByRole('heading', { name: '<script>API sample</script>' })
    fetcher.mockImplementation(async () => new Response(JSON.stringify({ detail: 'Read budget exceeded' }), { status: 503 }))
    await userEvent.click(screen.getByRole('button', { name: 'Refresh ledger' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Read budget exceeded')
    expect(screen.queryByRole('link', { name: 'Open report' })).toBeNull()
    expect(fetcher).toHaveBeenCalledTimes(2)
  })
})
