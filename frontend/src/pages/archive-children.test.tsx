import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import ArchiveChildren, { archivePollInterval } from './archive-children'
import type { ArchivePage } from '../lib/api'

const payload: ArchivePage = { parent_id: 42, parent_filename: 'outer.zip', parent_status: 'completed',
  parent_scan_id: null, batch_id: 1, archive_mode: 'lazy', attempt_count: 2, next_after: 44,
  items: [43, 44].map(id => ({ id, path: '<script>alert(1)</script>', path_truncated: false, filename: 'child.zip',
    size_bytes: 12, status: 'failed', risk_score: 0, risk_level: 'info', has_children: id === 43 })) }

function mount(page = payload, path = '/scans/42/children') {
  const fetcher = vi.fn(async (_url: string) => new Response(JSON.stringify(page)))
  vi.stubGlobal('fetch', fetcher)
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><Routes>
    <Route path="/scans/:scanId/children" element={<ArchiveChildren />} /></Routes></MemoryRouter></QueryClientProvider>)
  return fetcher
}

describe('Archive child navigation', () => {
  it('renders duplicate paths as text with distinct ID links, never a clean decision', async () => {
    mount()
    const paths = await screen.findAllByRole('link', { name: '<script>alert(1)</script>' })
    expect(paths.map(link => link.getAttribute('href'))).toEqual(['/scans/43', '/scans/44'])
    expect(screen.getByRole('link', { name: 'Browse children of #43' })).toHaveAttribute('href', '/scans/43/children')
    expect(document.querySelector('script')).toBeNull()
    expect(within(screen.getByRole('region', { name: 'Archive child scans' })).getAllByText('failed')).toHaveLength(2)
    expect(screen.getByText(/Empty or completed rows do not prove clean/)).toBeInTheDocument()
  })
  it('uses attempt-fenced keyset pagination and resets to the first page', async () => {
    const fetcher = mount()
    await screen.findByText('outer.zip')
    await userEvent.click(screen.getByRole('button', { name: 'Next page' }))
    await waitFor(() => expect(fetcher.mock.calls.at(-1)?.[0]).toContain('after=44&attempt=2'))
    await userEvent.click(screen.getByRole('button', { name: 'First page' }))
    await waitFor(() => expect(fetcher.mock.calls.at(-1)?.[0]).not.toContain('after='))
  })
  it('applies literal filters only on submit and drops the old cursor', async () => {
    const fetcher = mount(payload, '/scans/42/children?after=41&attempt=2')
    await screen.findByText('outer.zip')
    await userEvent.type(screen.getByRole('textbox', { name: 'Search archive paths' }), '%_!')
    expect(fetcher).toHaveBeenCalledTimes(1)
    await userEvent.click(screen.getByRole('button', { name: 'Apply filters' }))
    await waitFor(() => expect(fetcher.mock.calls.at(-1)?.[0]).toContain('q=%25_%21'))
    expect(fetcher.mock.calls.at(-1)?.[0]).not.toContain('after=')
  })
  it('hides cached rows on retry conflict and can restart pagination', async () => {
    const fetcher = mount(payload, '/scans/42/children?after=41&attempt=2')
    await screen.findByText('outer.zip')
    fetcher.mockImplementationOnce(async () => new Response(JSON.stringify({ detail: 'The parent scan has a new attempt.' }), { status: 409 }))
    await userEvent.click(screen.getByRole('button', { name: 'Refresh contents' }))
    await screen.findByRole('alert')
    expect(screen.queryByRole('region', { name: 'Archive child scans' })).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Return to first page' }))
    await screen.findByRole('region', { name: 'Archive child scans' })
    expect(fetcher.mock.calls.at(-1)?.[0]).not.toContain('after=')
  })
  it('explains empty results without claiming extraction succeeded', async () => {
    mount({ ...payload, items: [], next_after: null })
    await screen.findByRole('heading', { name: 'No registered children on this page' })
    expect(screen.getByText(/Lazy extraction may not have run/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Next page' })).toBeDisabled()
  })
  it('rejects invalid IDs without fetching', () => {
    const fetcher = mount(payload, '/scans/0/children')
    expect(screen.getByRole('heading', { name: 'Invalid scan ID' })).toBeInTheDocument()
    expect(fetcher).not.toHaveBeenCalled()
  })
  it('polls active parents or children only on the first page', () => {
    expect(archivePollInterval('', payload)).toBe(false)
    expect(archivePollInterval('', { ...payload, parent_status: 'finalizing' })).toBe(3000)
    const active = { ...payload, items: [{ ...payload.items[0], status: 'running' }] }
    expect(archivePollInterval('', active)).toBe(3000)
    expect(archivePollInterval('44', active)).toBe(false)
    expect(archivePollInterval('')).toBe(false)
  })
})
