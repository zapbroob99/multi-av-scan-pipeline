import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import ScanPrint from './scan-print'

const REPORT = {
  scan_id: 7, source: 'manual', filename: 'sample.bin', case_name: 'Case A', note: 'analyst note',
  status: 'completed', content_type: 'application/octet-stream', size_bytes: 2048, sha256: 'a'.repeat(64),
  attempt_count: 1, created_at: '2026-09-20 10:00:00', completed_at: '2026-09-20 10:01:00',
  generated_at: '2026-09-20 10:05:00',
  summary: { verdict: 'medium', risk_score: 55, assessment_reasons: ['One engine detected'],
    detection_label: '1 of 2 engines detected', detection_detail: 'ClamAV flagged this sample',
    detected_engines: ['ClamAV'], coverage_label: '2 of 2 required engines ran',
    coverage_detail: 'All required detection engines completed', coverage_ran: 2, coverage_total: 2,
    coverage_unavailable: [] },
  decision: { action: 'review', label: 'Needs review', tone: 'warning', confidence: 'medium',
    policy: 'default', reason: 'Detection recorded', reasons: ['ClamAV detection'] },
  decision_warning: null,
  findings: [{ engine: 'ClamAV', severity: 'medium', finding: 'Eicar.Test',
    title: '<script>title</script>', matched_evidence: ['offset 0'], classification: ['test'] }],
  findings_truncated: true,
  engines: [{ engine_name: 'ClamAV', status: 'completed', detected: true, severity: 'medium', confidence: 90,
    signature: 'Eicar.Test', duration_ms: 42, error_message: null, raw_output: '<b>bounded output</b>',
    output_truncated: true }],
}

function mount(path = '/scans/7/print', payload: object = REPORT, status = 200) {
  const fetcher = vi.fn(async () => new Response(JSON.stringify(payload), { status }))
  vi.stubGlobal('fetch', fetcher)
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter initialEntries={[path]}>
    <Routes><Route path="/scans/:scanId/print" element={<ScanPrint />} />
      <Route path="/api-ledger/scans/:scanId/print" element={<ScanPrint automation />} /></Routes>
  </MemoryRouter></QueryClientProvider>)
  return fetcher
}

describe('Printable report', () => {
  it('renders the bounded report as inert text and marks what was truncated', async () => {
    const fetcher = mount()
    await screen.findByText('sample.bin')
    expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/scans/7/print', expect.anything())
    expect(screen.getByText('<script>title</script>')).toBeInTheDocument()
    expect(document.querySelector('script')).toBeNull()
    expect(screen.getByLabelText('ClamAV raw output text')).toHaveTextContent('<b>bounded output</b>')
    expect(document.querySelector('pre b')).toBeNull()
    expect(screen.getByText(/Findings list truncated for printing/)).toBeInTheDocument()
    expect(screen.getByText(/Output truncated for printing/)).toBeInTheDocument()
    expect(screen.getByText('Needs review')).toBeInTheDocument()
  })

  it('reads the automation route for automation scans', async () => {
    const fetcher = mount('/api-ledger/scans/7/print', { ...REPORT, source: 'api' })
    await screen.findByText('sample.bin')
    expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/api-ledger/scans/7/print', expect.anything())
    expect(screen.getByRole('link', { name: 'Back to report' })).toHaveAttribute('href', '/api-ledger/scans/7')
  })

  it('invokes printing only on request and never automatically', async () => {
    const print = vi.fn()
    vi.stubGlobal('print', print)
    mount()
    await screen.findByText('sample.bin')
    expect(print).not.toHaveBeenCalled()
    await userEvent.click(screen.getByRole('button', { name: 'Print' }))
    expect(print).toHaveBeenCalledTimes(1)
  })

  it('hides the report on a refused read instead of showing a partial sheet', async () => {
    const fetcher = mount('/scans/7/print', { detail: 'Printable report exceeds the 2 MiB browser response limit.' }, 413)
    await screen.findByRole('alert')
    expect(screen.getByRole('alert')).toHaveTextContent('2 MiB')
    expect(screen.queryByText('sample.bin')).toBeNull()
    expect(fetcher).toHaveBeenCalledTimes(1)
  })

  it('rejects a non-numeric scan ID before any request', async () => {
    const fetcher = vi.fn()
    vi.stubGlobal('fetch', fetcher)
    render(<QueryClientProvider client={new QueryClient()}><MemoryRouter initialEntries={['/scans/abc/print']}>
      <Routes><Route path="/scans/:scanId/print" element={<ScanPrint />} /></Routes></MemoryRouter></QueryClientProvider>)
    expect(screen.getByText('Invalid scan ID')).toBeInTheDocument()
    expect(fetcher).not.toHaveBeenCalled()
  })
})
