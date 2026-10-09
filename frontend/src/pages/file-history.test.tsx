import { render, screen, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import FileHistory, { reportPath } from './file-history'

const DIGEST = 'c'.repeat(64)
const HISTORY = { sha256: DIGEST, seen: true, scan_count: 4, detected_count: 2, first_seen_at: 1790000000, last_seen_at: 1791000000,
  last_detected_at: 1790500000, last_status: 'completed', last_verdict: 'critical', last_risk_score: 90, last_rule_action: null,
  last_not_allowed: null, last_not_allowed_label: null, hash_list: 'block',
  exceptions: [{ id: 7, scope: '#2 Gate', reason: '<b>Vendor tool</b>' }],
  last_engines: [
    { engine_name: 'ClamAV', status: 'completed', detected: true, signature: 'Win.Test.EICAR_HDB-1', engine_version: '1.4.2', signature_version: '27771' },
    { engine_name: 'Defender', status: 'failed', detected: false, signature: null, engine_version: null, signature_version: null }],
  recent_scans: [
    { id: 41, source: 'icap', scan_role: 'single', status: 'completed', verdict: 'critical', risk_score: 90, created_at: '2026-09-20 10:00:00',
      filename: '<script>x</script>.exe', client_id: 2, client_name: 'Gate', exception_id: null, not_allowed: null, not_allowed_label: null, rule_action: null },
    { id: 40, source: 'manual', scan_role: 'child', status: 'completed', verdict: 'info', risk_score: 0, created_at: '2026-09-19 10:00:00',
      filename: 'member.exe', client_id: null, client_name: null, exception_id: null, not_allowed: null, not_allowed_label: null, rule_action: null }] }

function mount(path: string, body: object = HISTORY, role = 'admin') {
  const fetcher = vi.fn(async (_url: string) => new Response(JSON.stringify(body), { status: 200 }))
  vi.stubGlobal('fetch', fetcher)
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter initialEntries={[path]}><Routes>
    <Route path="/files/:sha256" element={<FileHistory session={{ user: { id: 1, username: 'u', role }, csrf_token: 'csrf' }} />} />
  </Routes></MemoryRouter></QueryClientProvider>)
  return fetcher
}

describe('File history', () => {
  it('shows recorded facts, engines, lists and recent scans as inert text', async () => {
    const fetcher = mount('/files/' + DIGEST.toUpperCase())
    const stats = await screen.findByLabelText('Recorded file history')
    expect(within(stats).getByText('4')).toBeInTheDocument()
    expect(within(stats).getByText('2')).toBeInTheDocument()
    expect(String(fetcher.mock.calls[0][0])).toContain('/api/ui/v1/files/' + DIGEST)
    const engines = screen.getByRole('region', { name: 'Latest engine results' })
    expect(within(engines).getByText('Win.Test.EICAR_HDB-1')).toBeInTheDocument()
    expect(within(engines).getByText('27771')).toBeInTheDocument()
    expect(within(engines).getByText('failed')).toBeInTheDocument()
    expect(screen.getByText(/^Blocklist/)).toBeInTheDocument()
    expect(screen.getByText(/#7 · #2 Gate · <b>Vendor tool<\/b>/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '<script>x</script>.exe' })).toHaveAttribute('href', '/api-ledger/scans/41')
    expect(screen.getByRole('link', { name: 'member.exe' })).toHaveAttribute('href', '/scans/40')
    expect(screen.getByText(/Archive member/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Ask external engines' })).toHaveAttribute('href', '/hash-scan?sha256=' + DIGEST)
    expect(document.querySelector('script, b')).toBeNull()
  })
  it('hides administrator links from analysts', async () => {
    mount('/files/' + DIGEST, HISTORY, 'analyst')
    await screen.findByLabelText('Recorded file history')
    expect(screen.queryByRole('link', { name: 'Hash list' })).toBeNull()
    expect(screen.queryByRole('link', { name: 'Exceptions' })).toBeNull()
  })
  it('says a never-scanned file proves nothing', async () => {
    mount('/files/' + DIGEST, { ...HISTORY, seen: false, scan_count: 0, detected_count: 0, last_engines: [], recent_scans: [], hash_list: null, exceptions: [] })
    expect(await screen.findByText('MASP has not scanned this file')).toBeInTheDocument()
    expect(screen.getByText(/Not listed/)).toBeInTheDocument()
  })
  it('says the history outlives scans that are no longer kept', async () => {
    mount('/files/' + DIGEST, { ...HISTORY, recent_scans: [] })
    expect(await screen.findByText(/scans themselves are no longer kept/)).toBeInTheDocument()
  })
  it('refuses an invalid digest without asking the server', () => {
    const fetcher = mount('/files/not-a-hash')
    expect(screen.getByRole('heading', { name: 'Invalid SHA-256' })).toBeInTheDocument()
    expect(fetcher).not.toHaveBeenCalled()
  })
  it('links only sources that have a report screen', () => {
    expect(reportPath({ id: 1, source: 'manual' })).toBe('/scans/1')
    expect(reportPath({ id: 2, source: 'api' })).toBe('/api-ledger/scans/2')
    expect(reportPath({ id: 3, source: 'storage' })).toBeNull()
  })
})
