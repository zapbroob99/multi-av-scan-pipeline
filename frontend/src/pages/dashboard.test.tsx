import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import Dashboard, { historyPollInterval } from './dashboard'
import type { ScanPreview } from '../lib/api'

const sample: ScanPreview = { id: 24, filename: '<img src=x onerror=alert(1)>', sha256: 'a'.repeat(64),
  size_bytes: 512, case_name: 'Case A', status: 'failed', risk_score: 0, risk_level: 'info', created_at: '2026-09-08 12:00:00' }

function mount(path = '/dashboard', failHistory = false) {
  const fetcher = vi.fn(async (url: string) => {
    if (url.includes('/summary')) return new Response(JSON.stringify({ total: 24, active: 1, high_risk: 2,
      enabled_engines: 1, generated_at: '2026-09-08T12:00:00Z', refresh_after_seconds: 30 }))
    if (failHistory) return new Response(JSON.stringify({ detail: 'Database unavailable' }), { status: 503 })
    return new Response(JSON.stringify({ items: [sample], next_before: 24 }))
  })
  vi.stubGlobal('fetch', fetcher)
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><Dashboard /></MemoryRouter></QueryClientProvider>)
  return fetcher
}

describe('Dashboard', () => {
  it('keeps failed zero-score scans distinct from a clean verdict and renders untrusted filenames as text', async () => {
    mount()
    expect(await screen.findByRole('link', { name: sample.filename })).toHaveAttribute('href', '/scans/24')
    expect(screen.getByText('failed', { selector: 'span' })).toBeInTheDocument()
    expect(screen.getByText('0 / 100 · info')).toBeInTheDocument()
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
})
