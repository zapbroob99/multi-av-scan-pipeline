import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import Report, { reportPollInterval } from './scan-report'
import type { ScanReport } from '../lib/api'

const payload: ScanReport = { id: 42, filename: 'safe.bin', sha256: 'a'.repeat(64), size_bytes: 12,
  case_name: 'Case A', note: '', status: 'completed', risk_score: 0, risk_level: 'info', attempt_count: 1,
  created_at: '2026-09-08 12:00:00', completed_at: null, last_error: null, batch_id: null, parent_scan_id: null,
  detected_engines: 0, required_engines: 1, completed_engines: 1, unavailable: [], warning: null, coverage_basis: 'routing_snapshot',
  decision: { action: 'allow', label: 'Allow', tone: 'success', confidence: 'high', policy: 'clean_full_coverage', reason: 'Full coverage completed.', reasons: [] },
  engines: [{ result_id: 7, name: 'AV', required: true, status: 'completed', detected: false, signature: null, error: null, duration_ms: 10 }] }

function mount(report = payload, path = '/scans/42', automation = false) {
  const fetcher = vi.fn(async (url: string) => new Response(JSON.stringify(url.includes('/results/') ? {
    result_id: 7, raw_output: '<script>alert(1)</script>', details_json: '{}', findings_json: '[]', truncated: ['raw_output'],
  } : report)))
  vi.stubGlobal('fetch', fetcher)
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><Routes>
    <Route path="/scans/:scanId" element={<Report automation={automation} />} /></Routes></MemoryRouter></QueryClientProvider>)
  return fetcher
}

describe('Scan report', () => {
  it('uses the server decision and loads technical text only on demand', async () => {
    const fetcher = mount()
    await screen.findByRole('heading', { name: 'Allow' })
    expect(fetcher.mock.calls.some(([url]) => url.includes('/results/'))).toBe(false)
    await userEvent.click(screen.getByRole('button', { name: 'Show technical output for AV' }))
    expect(await screen.findByText('<script>alert(1)</script>')).toBeInTheDocument()
    expect(screen.getByText(/Truncated previews/)).toBeInTheDocument()
    expect(document.querySelector('script')).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Hide technical output for AV' }))
    expect(screen.queryByText('<script>alert(1)</script>')).toBeNull()
  })
  it('uses isolated automation routes and preserves inert technical rendering', async () => {
    const fetcher = mount({ ...payload, source: 'api', service_client_id: 3, batch_id: 8 }, '/scans/42', true)
    await screen.findByRole('heading', { name: 'Allow' })
    expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/api-ledger/scans/42', expect.anything())
    expect(screen.getByRole('link', { name: 'Open batch overview' })).toHaveAttribute('href', '/api-ledger/batches/8')
    expect(screen.getByRole('link', { name: 'Browse registered direct children' })).toHaveAttribute('href', '/api-ledger/scans/42/children')
    await userEvent.click(screen.getByRole('button', { name: 'Show technical output for AV' }))
    await screen.findByText('<script>alert(1)</script>')
    expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/api-ledger/scans/42/results/7', expect.anything())
    expect(screen.getByRole('link', { name: 'Full output for AV' })).toHaveAttribute('href', '/api-ledger/scans/42/results/7')
  })
  it('does not derive allow from a zero score or missing policy input', async () => {
    mount({ ...payload, decision: null, warning: 'Decision unavailable: incomplete policy.',
      completed_engines: 0, unavailable: ['AV missing'] })
    await screen.findByRole('heading', { name: 'Decision unavailable' })
    expect(screen.getByText('AV missing')).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Allow' })).toBeNull()
  })
  it('removes a prior allow card when a report refresh fails', async () => {
    const fetcher = mount()
    await screen.findByRole('heading', { name: 'Allow' })
    fetcher.mockImplementationOnce(async () => new Response(JSON.stringify({ detail: 'Scan no longer available' }), { status: 404 }))
    await userEvent.click(screen.getByRole('button', { name: 'Refresh report' }))
    await screen.findByRole('heading', { name: 'Report unavailable' })
    expect(screen.queryByRole('heading', { name: 'Allow' })).toBeNull()
  })
  it('rejects invalid IDs without fetching', () => {
    const fetcher = mount(payload, '/scans/9007199254740992')
    expect(screen.getByRole('heading', { name: 'Invalid scan ID' })).toBeInTheDocument()
    expect(fetcher).not.toHaveBeenCalled()
  })
  it('polls only active states including finalizing', () => {
    for (const status of ['queued', 'running', 'finalizing']) expect(reportPollInterval({ ...payload, status })).toBe(3000)
    for (const status of ['completed', 'failed']) expect(reportPollInterval({ ...payload, status })).toBe(false)
    expect(reportPollInterval()).toBe(false)
  })
})
