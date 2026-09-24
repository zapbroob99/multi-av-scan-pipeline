import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import BatchOverview, { batchPollInterval } from './batch-overview'
import type { BatchPage } from '../lib/api'

const payload: BatchPage = {
  batch_id: 7, filename: '<script>outer.zip</script>', filename_truncated: false,
  archive_mode: 'lazy_extract_on_detection', status: 'completed',
  counts: { total: 2, queued: 0, running: 0, completed: 1, failed: 1, malicious: 0, skipped: 0 },
  created_at: '2026-09-10 10:00:00', updated_at: '2026-09-10 10:01:00', completed_at: '2026-09-10 10:01:00',
  items: [{ id: 41, path: '<script>child.bin</script>', path_truncated: false, filename: 'child.bin',
    size_bytes: 12, parent_scan_id: 40, role: 'child', status: 'failed', risk_score: 0,
    risk_level: 'info', attempt_count: 0, created_at: '2026-09-10 10:00:00', completed_at: null }],
  next_after_id: 41, next_after_created: '2026-09-10 10:00:00',
}

function mount(page = payload, path = '/batches/7') {
  const fetcher = vi.fn(async (_url: string) => new Response(JSON.stringify(page)))
  vi.stubGlobal('fetch', fetcher)
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><Routes>
    <Route path="/batches/:batchId" element={<BatchOverview />} /></Routes></MemoryRouter></QueryClientProvider>)
  return fetcher
}

describe('Batch overview', () => {
  it('renders bounded registered scans as text and labels recorded risk', async () => {
    mount()
    expect(await screen.findByRole('heading', { name: 'Batch overview' })).toBeInTheDocument()
    expect(await screen.findByText('<script>outer.zip</script>')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '<script>child.bin</script>' })).toHaveAttribute('href', '/scans/41')
    expect(document.querySelector('script')).toBeNull()
    expect(screen.getByText(/do not prove clean coverage/)).toBeInTheDocument()
    expect(within(screen.getByRole('region', { name: 'Batch scans' })).getByText('Not scored')).toBeInTheDocument()
  })

  it('uses both keyset cursor fields and can return to the first page', async () => {
    const fetcher = mount()
    await screen.findByRole('region', { name: 'Batch scans' })
    await userEvent.click(screen.getByRole('button', { name: 'Next page' }))
    await waitFor(() => expect(fetcher.mock.calls.at(-1)?.[0]).toContain('after_id=41&after_created=2026-09-10+10%3A00%3A00'))
    await userEvent.click(screen.getByRole('button', { name: 'First page' }))
    await waitFor(() => expect(fetcher.mock.calls.at(-1)?.[0]).not.toContain('after_id='))
  })

  it('hides rows after a failed historical refresh and offers the first page', async () => {
    const fetcher = mount(payload, '/batches/7?after_id=41&after_created=2026-09-10+10%3A00%3A00')
    await screen.findByRole('region', { name: 'Batch scans' })
    fetcher.mockImplementationOnce(async () => new Response(JSON.stringify({ detail: 'Invalid batch cursor.' }), { status: 422 }))
    await userEvent.click(screen.getByRole('button', { name: 'Refresh batch' }))
    await screen.findByRole('alert')
    expect(screen.queryByRole('region', { name: 'Batch scans' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Return to first page' })).toBeInTheDocument()
  })

  it('polls active batches or rows only on the first page', () => {
    expect(batchPollInterval('', payload)).toBe(false)
    expect(batchPollInterval('', { ...payload, status: 'running' })).toBe(3000)
    expect(batchPollInterval('', { ...payload, items: [{ ...payload.items[0], status: 'queued' }] })).toBe(3000)
    expect(batchPollInterval('41', { ...payload, status: 'running' })).toBe(false)
    expect(batchPollInterval('')).toBe(false)
  })

  it('explains an empty page without claiming extraction completed', async () => {
    mount({ ...payload, items: [], next_after_id: null, next_after_created: null })
    expect(await screen.findByRole('heading', { name: 'No registered scans on this page' })).toBeInTheDocument()
  })

  it('rejects an invalid batch ID without fetching', () => {
    const fetcher = mount(payload, '/batches/0')
    expect(screen.getByRole('heading', { name: 'Invalid batch ID' })).toBeInTheDocument()
    expect(fetcher).not.toHaveBeenCalled()
  })
})
