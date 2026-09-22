import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import Retention from './retention'

function mount(fail = false) {
  const fetcher = vi.fn(async (_url: string, options?: RequestInit) => options?.method === 'POST'
    ? new Response(JSON.stringify(fail ? { detail: 'Unavailable' } : { requested_count: 1, deleted_ids: [7], blocked_ids: [], cleanup_failed_ids: [7] }), { status: fail ? 503 : 200 })
    : new Response(JSON.stringify({ days: 30, batch_size: 100, cutoff: '2026-08-01', next_after: null,
      items: [{ scan_id: 7, attempt: 2, job_revision: 8, filename: '<script>sample</script>', source: 'api', status: 'completed', created_at: '2000-01-01' }] })))
  vi.stubGlobal('fetch', fetcher)
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter><Retention session={{ user: { id: 1, username: 'admin', role: 'admin' }, csrf_token: 'csrf' }} /></MemoryRouter></QueryClientProvider>)
  return fetcher
}

describe('Retention', () => {
  it('requires confirmation and sends only reviewed IDs and fences with CSRF', async () => {
    const fetcher = mount()
    await screen.findByText('<script>sample</script>')
    expect(document.querySelector('script')).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Review deletion' }))
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(fetcher).toHaveBeenCalledTimes(1)
    await userEvent.click(screen.getByRole('button', { name: 'Review deletion' }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm retention deletion' }))
    await screen.findByText('Deleted IDs: 7')
    expect(screen.getByText('File cleanup failed for deleted IDs: 7')).toBeInTheDocument()
    const writes = fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')
    expect(writes).toHaveLength(1)
    expect(JSON.parse(String(writes[0][1]?.body))).toEqual({ days: 30, batch_size: 100, scans: [{ scan_id: 7, attempt: 2, job_revision: 8 }] })
    expect(writes[0][1]?.headers).toMatchObject({ 'X-CSRF-Token': 'csrf' })
    expect(screen.queryByRole('button', { name: 'Review deletion' })).toBeNull()
  })
  it('does not replay uncertain writes and requires refresh before another review', async () => {
    const fetcher = mount(true)
    await userEvent.click(await screen.findByRole('button', { name: 'Review deletion' }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm retention deletion' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Some records may already have been deleted')
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1)
    expect(screen.queryByRole('button', { name: 'Review deletion' })).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Refresh preview' }))
    expect(await screen.findByRole('button', { name: 'Review deletion' })).toBeEnabled()
  })
})
