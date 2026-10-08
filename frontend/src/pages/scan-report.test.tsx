import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import Report, { reportPollInterval } from './scan-report'
import type { ScanReport, Session } from '../lib/api'

const payload: ScanReport = { id: 42, filename: 'safe.bin', sha256: 'a'.repeat(64), size_bytes: 12,
  case_name: 'Case A', note: '', status: 'completed', risk_score: 0, risk_level: 'info', attempt_count: 1,
  created_at: '2026-09-08 12:00:00', completed_at: null, last_error: null, batch_id: null, parent_scan_id: null,
  detected_engines: 0, required_engines: 1, completed_engines: 1, unavailable: [], warning: null, coverage_basis: 'routing_snapshot',
  decision: { action: 'allow', label: 'Allow', tone: 'success', confidence: 'high', policy: 'clean_full_coverage', reason: 'Full coverage completed.', reasons: [] },
  engines: [{ result_id: 7, name: 'AV', required: true, status: 'completed', detected: false, signature: null, error: null, duration_ms: 10 }] }

const ADMIN = { csrf_token: 'csrf', user: { id: 1, username: 'admin', role: 'admin' } } as unknown as Session

function mount(report = payload, path = '/scans/42', automation = false, admin = false) {
  const fetcher = vi.fn(async (url: string, init?: RequestInit) => init?.method === 'POST' ? new Response(JSON.stringify({ id: 9 }), { status: 201 })
    : new Response(JSON.stringify(url.includes('/results/') ? {
    result_id: 7, raw_output: '<script>alert(1)</script>', details_json: '{}', findings_json: '[]', truncated: ['raw_output'],
  } : report)))
  vi.stubGlobal('fetch', fetcher)
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><Routes>
    <Route path="/scans/:scanId" element={<Report automation={automation} session={admin ? ADMIN : undefined} />} /></Routes></MemoryRouter></QueryClientProvider>)
  return fetcher
}

describe('Scan report', () => {
  it('lets administrators add an exception for a blocked file from the report', async () => {
    const blocked = { ...payload, source: 'icap', service_client_id: 3,
      decision: { ...payload.decision!, action: 'block', label: 'Block', policy: 'detected' } }
    const fetcher = mount(blocked, '/scans/42', true, true)
    await userEvent.click(await screen.findByRole('button', { name: 'Add an exception for this file' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByLabelText('Applies to')).toHaveValue('client')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Add exception' }))
    expect(within(dialog).getByRole('alert')).toHaveTextContent('A reason is required.')
    await userEvent.type(within(dialog).getByLabelText('Reason'), 'Vendor build')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Add exception' }))
    await waitFor(() => expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(true))
    const [url, init] = fetcher.mock.calls.find(([, call]) => call?.method === 'POST')!
    expect(url).toBe('/api/ui/v1/exceptions')
    expect(JSON.parse(String(init!.body))).toEqual({ sha256: 'a'.repeat(64), reason: 'Vendor build', service_client_id: 3, expires_in_days: null })
    expect(await screen.findByText(/Exception #9 added/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Add an exception for this file' })).toBeNull()
  })
  it('never offers an exception to analysts', async () => {
    mount({ ...payload, decision: { ...payload.decision!, action: 'block', label: 'Block' } })
    await screen.findByRole('heading', { name: 'Block' })
    expect(screen.queryByText('Add an exception for this file')).toBeNull()
  })
  it('names the engine and signatures that produced each result', async () => {
    mount({ ...payload, engines: [{ ...payload.engines[0], engine_version: '1.4.2', signature_version: '27771' }] })
    expect(await screen.findByText('Engine 1.4.2 · Signatures 27771')).toBeInTheDocument()
  })
  it('marks a file allowed by exception', async () => {
    mount({ ...payload, exception_id: 5, decision: { ...payload.decision!, label: 'Allow (exception)', policy: 'exception_allow' } }, '/scans/42', false, true)
    await screen.findByRole('heading', { name: 'Allow (exception)' })
    expect(screen.getByTitle(/Allowed by exception #5/)).toHaveTextContent('Exception#5')
    expect(screen.getByRole('link', { name: 'Review or revoke exception #5' })).toBeInTheDocument()
    expect(screen.queryByText('Add an exception for this file')).toBeNull()
  })
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
  it('keeps polling when the container finished but its archive members are pending', async () => {
    const report: ScanReport = { ...payload, batch_id: 8, decision: {
      action: 'wait', label: 'Wait', tone: 'neutral', confidence: 'low',
      policy: 'archive_members_in_progress', reason: 'Archive members are still being scanned.', reasons: [],
    } }
    expect(reportPollInterval(report)).toBe(3000)
    mount(report)
    await screen.findByRole('heading', { name: 'Wait' })
    expect(screen.queryByRole('heading', { name: 'Allow' })).toBeNull()
    expect(screen.getByText(/The risk, coverage and engine results below describe this file/)).toBeInTheDocument()
  })
})
