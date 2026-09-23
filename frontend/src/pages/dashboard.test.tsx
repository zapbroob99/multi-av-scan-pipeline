import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import Dashboard, { historyPollInterval } from './dashboard'
import type { ScanPreview } from '../lib/api'

const sample: ScanPreview = { id: 24, filename: '<img src=x onerror=alert(1)>', sha256: 'a'.repeat(64),
  size_bytes: 512, case_name: 'Case A', status: 'failed', risk_score: 0, risk_level: 'info',
  attempt_count: 3, job_revision: 9, created_at: '2026-09-08 12:00:00' }

function mount(path = '/dashboard', failHistory = false, role = 'admin') {
  const fetcher = vi.fn(async (url: string, options?: RequestInit) => {
    if (options?.method === 'DELETE') return new Response(JSON.stringify({ requested_count: 1,
      deleted_ids: [24], blocked_ids: [], cleanup_failed_ids: [] }))
    if (url.includes('/summary')) return new Response(JSON.stringify({ total: 24, active: 1, high_risk: 2,
      enabled_engines: 1, generated_at: '2026-09-08T12:00:00Z', refresh_after_seconds: 30 }))
    if (failHistory) return new Response(JSON.stringify({ detail: 'Database unavailable' }), { status: 503 })
    return new Response(JSON.stringify({ items: [sample], next_before: 24 }))
  })
  vi.stubGlobal('fetch', fetcher)
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><Dashboard
    session={{ user: { id: 1, username: 'user', role }, csrf_token: 'csrf' }} /></MemoryRouter></QueryClientProvider>)
  return fetcher
}

describe('Dashboard', () => {
  it('keeps failed zero-score scans distinct from a clean verdict and renders untrusted filenames as text', async () => {
    mount()
    expect(await screen.findByRole('link', { name: sample.filename })).toHaveAttribute('href', '/scans/24')
    expect(screen.getByText('failed', { selector: 'span' })).toBeInTheDocument()
    // The badge must carry the recorded level and score without reading as an
    // alert, while the separate failed status stays visible beside it.
    const risk = document.querySelector('tbody .risk-badge')
    expect(risk).toHaveTextContent('info')
    expect(risk).toHaveTextContent('0 / 100')
    expect(risk).not.toHaveClass('risk-badge-alert')
    expect(document.querySelector('tr.row-alert')).toBeNull()
    expect(screen.getByText(/Risk is not a clean verdict/)).toBeInTheDocument()
    expect(document.querySelector('img')).toBeNull()
  })
  it('submits filters explicitly, resets the cursor and requests only a bounded page', async () => {
    const fetcher = mount('/dashboard?before=40')
    await screen.findByRole('link', { name: sample.filename })
    const count = fetcher.mock.calls.length
    await userEvent.type(screen.getByLabelText('Search scans'), 'eicar%')
    expect(fetcher).toHaveBeenCalledTimes(count)
    await userEvent.selectOptions(screen.getByLabelText('Status'), 'active')
    await userEvent.click(screen.getByRole('button', { name: 'Apply filters' }))
    await waitFor(() => expect(fetcher.mock.calls.some(([url]) =>
      url.includes('q=eicar%25') && url.includes('status=active') && url.includes('limit=20') && !url.includes('before='))).toBe(true))
  })
  it('navigates by cursor, preserves filters and can return to latest', async () => {
    const fetcher = mount('/dashboard?q=abc&risk=high')
    await screen.findByRole('link', { name: sample.filename })
    await userEvent.click(screen.getByRole('button', { name: 'Older scans' }))
    await screen.findByText(/auto-refresh paused/)
    expect(fetcher.mock.calls.some(([url]) => url.includes('before=24') && url.includes('q=abc') && url.includes('risk=high'))).toBe(true)
    await userEvent.click(screen.getByRole('button', { name: 'Latest scans' }))
    expect(screen.queryByRole('button', { name: 'Latest scans' })).toBeNull()
  })
  it('shows history failures instead of presenting an empty successful result', async () => {
    mount('/dashboard', true)
    expect(await screen.findByRole('alert')).toHaveTextContent('Database unavailable')
    expect(screen.queryByText('No scans found')).toBeNull()
  })
  it('polls only the latest history page', () => {
    expect(historyPollInterval('')).toBe(20000)
    expect(historyPollInterval('24')).toBe(false)
  })
  it('submits an admin bulk deletion once with displayed fences', async () => {
    const fetcher = mount()
    await userEvent.click(await screen.findByRole('checkbox', { name: 'Select scan 24' }))
    await userEvent.click(screen.getByRole('button', { name: 'Delete selected (1)' }))
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'DELETE')).toHaveLength(0)
    await userEvent.click(screen.getByRole('button', { name: 'Confirm deletion' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Deleted 1 of 1 selected scans')
    const writes = fetcher.mock.calls.filter(([, options]) => options?.method === 'DELETE')
    expect(writes).toHaveLength(1)
    expect(JSON.parse(String(writes[0][1]?.body))).toEqual({ scans: [{ scan_id: 24, attempt: 3, job_revision: 9 }] })
    expect(writes[0][1]?.headers).toMatchObject({ 'X-CSRF-Token': 'csrf' })
  })
  it('keeps bulk deletion unavailable to analysts', async () => {
    mount('/dashboard', false, 'analyst')
    await screen.findByRole('link', { name: sample.filename })
    expect(screen.queryByRole('checkbox')).toBeNull()
    expect(screen.queryByRole('button', { name: /Delete selected/ })).toBeNull()
  })
})
