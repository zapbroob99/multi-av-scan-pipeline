import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import HashScan from './hash-scan'

const SEEN = { sha256: 'a'.repeat(64), seen: true, scan_count: 3, detected_count: 1, first_seen_at: 1790000000,
  last_seen_at: 1791000000, last_detected_at: 1790500000, last_status: 'completed', last_verdict: 'critical', last_risk_score: 90,
  last_rule_action: null, last_not_allowed: null, last_not_allowed_label: null, hash_list: null, exceptions: [], recent_scans: [],
  last_engines: [{ engine_name: 'ClamAV', status: 'completed', detected: true, signature: 'Win.Test.EICAR_HDB-1',
    engine_version: '1.4.2', signature_version: '27771' }] }

function mount(fail = false, { history = SEEN as object, path = '/hash-scan' } = {}) {
  const fetcher = vi.fn(async (url: string, options?: RequestInit) => {
    if (url.includes('/api/ui/v1/files/')) return new Response(JSON.stringify(history), { status: 200 })
    return new Response(JSON.stringify(options?.method === 'POST'
    ? fail ? { detail: 'Quota exhausted' } : { sha256: 'a'.repeat(64), action: 'review', reason: 'Backend requires review',
      results: [{ id: 1, name: '<script>Engine</script>', action: 'review', found: true, status: 'suspicious',
        stats: { malicious: 0, suspicious: 2, undetected: 60, harmless: 1, total: 70 }, last_analysis_date: '2026-09-20T10:00:00+00:00',
        permalink: 'https://www.virustotal.com/gui/file/' + 'a'.repeat(64), cached: false, duration_ms: 42 }] }
    : { engines: [{ id: 1, name: '<script>Engine</script>' }] }), { status: fail && options?.method === 'POST' ? 503 : 200 })
  })
  vi.stubGlobal('fetch', fetcher)
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter initialEntries={[path]}><HashScan session={{ user: { id: 1, username: 'analyst', role: 'analyst' }, csrf_token: 'csrf' }} /></MemoryRouter></QueryClientProvider>)
  return fetcher
}

const posts = (fetcher: ReturnType<typeof vi.fn>) => fetcher.mock.calls.filter(([, options]) => (options as RequestInit | undefined)?.method === 'POST')
const ASK = { name: 'Ask external engines (uses quota)' }

describe('Hash lookup', () => {
  it('posts explicitly with CSRF and displays the backend decision as inert text', async () => {
    const fetcher = mount()
    await screen.findByText(/Enabled hash engines/)
    expect(fetcher).toHaveBeenCalledTimes(1)
    await userEvent.type(screen.getByLabelText('SHA-256'), 'a'.repeat(64))
    await userEvent.click(screen.getByRole('button', ASK))
    await screen.findByRole('heading', { name: 'Reputation decision: review' })
    expect(screen.getByText('Backend requires review')).toBeInTheDocument()
    expect(screen.getByText(/Manual review required/)).toBeInTheDocument()
    expect(screen.getByText(/Provider status: suspicious/)).toBeInTheDocument()
    expect(screen.getByText('0 malicious · 2 suspicious · 60 undetected · 1 harmless (of 70)')).toBeInTheDocument()
    expect(screen.getByText('Live provider request · 42 ms')).toBeInTheDocument()
    const report = screen.getByRole('link', { name: 'Open provider report' })
    expect(report).toHaveAttribute('rel', 'noopener noreferrer')
    expect(report.getAttribute('href')).toMatch(/^https:\/\/www\.virustotal\.com\//)
    expect(document.querySelector('script')).toBeNull()
    const write = posts(fetcher)[0]!
    expect(write[1]?.headers).toMatchObject({ 'X-CSRF-Token': 'csrf' })
    expect(JSON.parse(String(write[1]?.body))).toEqual({ sha256: 'a'.repeat(64) })
    await userEvent.clear(screen.getByLabelText('SHA-256'))
    expect(screen.queryByRole('region', { name: 'Hash lookup result' })).toBeNull()
  })
  it('counts hexadecimal characters and flags invalid input before submitting', async () => {
    mount()
    await screen.findByText(/Enabled hash engines/)
    expect(screen.getByText('0 / 64 hexadecimal characters')).toBeInTheDocument()
    await userEvent.type(screen.getByLabelText('SHA-256'), 'abc')
    expect(screen.getByText('3 / 64 hexadecimal characters')).toBeInTheDocument()
    await userEvent.type(screen.getByLabelText('SHA-256'), 'z')
    expect(screen.getByText(/Only hexadecimal characters/)).toBeInTheDocument()
    await userEvent.clear(screen.getByLabelText('SHA-256'))
    await userEvent.type(screen.getByLabelText('SHA-256'), 'b'.repeat(64))
    expect(screen.getByText('Valid SHA-256 length.')).toBeInTheDocument()
  })
  it('does not retry failures or display an allow decision', async () => {
    const fetcher = mount(true)
    await screen.findByText(/Enabled hash engines/)
    await userEvent.type(screen.getByLabelText('SHA-256'), 'a'.repeat(64))
    await userEvent.click(screen.getByRole('button', ASK))
    expect(await screen.findByText(/consumed quota/)).toBeInTheDocument()
    expect(screen.queryByRole('region', { name: 'Hash lookup result' })).toBeNull()
    expect(posts(fetcher)).toHaveLength(1)
  })
  it('shows MASP records first, for free, and keeps them out of the external decision', async () => {
    const fetcher = mount(false, { path: '/hash-scan?sha256=' + 'A'.repeat(64) })
    const local = await screen.findByRole('region', { name: 'Seen in MASP' })
    expect(screen.getByLabelText('SHA-256')).toHaveValue('A'.repeat(64))
    await within(local).findByText(/Scanned 3 times · 1 with a detection/)
    expect(within(local).getByText('Win.Test.EICAR_HDB-1')).toBeInTheDocument()
    expect(within(local).getByRole('link', { name: 'Open file history' })).toHaveAttribute('href', '/files/' + 'a'.repeat(64))
    expect(fetcher.mock.calls.some(([url]) => String(url).includes('/api/ui/v1/files/' + 'a'.repeat(64)))).toBe(true)
    // Enter in the field asks no provider; only the explicit button spends quota.
    await userEvent.type(screen.getByLabelText('SHA-256'), '{Enter}')
    expect(posts(fetcher)).toHaveLength(0)
    await userEvent.click(screen.getByRole('button', ASK))
    await screen.findByRole('heading', { name: 'Reputation decision: review' })
    expect(screen.getByRole('region', { name: 'Seen in MASP' })).toBeInTheDocument()
  })
  it('says plainly when MASP has never scanned the file', async () => {
    mount(false, { history: { ...SEEN, seen: false, scan_count: 0, detected_count: 0, last_engines: [] }, path: '/hash-scan?sha256=' + 'b'.repeat(64) })
    expect(await screen.findByText(/MASP has not scanned this file/)).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Open file history' })).toBeNull()
  })
})
