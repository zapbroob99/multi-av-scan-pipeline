import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import HashScan from './hash-scan'

function mount(fail = false) {
  const fetcher = vi.fn(async (_url: string, options?: RequestInit) => new Response(JSON.stringify(options?.method === 'POST'
    ? fail ? { detail: 'Quota exhausted' } : { sha256: 'a'.repeat(64), action: 'review', reason: 'Backend requires review',
      results: [{ id: 1, name: '<script>Engine</script>', action: 'review', found: true, status: 'suspicious',
        stats: { malicious: 0, suspicious: 2, undetected: 60, harmless: 1, total: 70 }, last_analysis_date: '2026-09-20T10:00:00+00:00',
        permalink: 'https://www.virustotal.com/gui/file/' + 'a'.repeat(64), cached: false, duration_ms: 42 }] }
    : { engines: [{ id: 1, name: '<script>Engine</script>' }] }), { status: fail && options?.method === 'POST' ? 503 : 200 }))
  vi.stubGlobal('fetch', fetcher)
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter><HashScan session={{ user: { id: 1, username: 'analyst', role: 'analyst' }, csrf_token: 'csrf' }} /></MemoryRouter></QueryClientProvider>)
  return fetcher
}

describe('Hash lookup', () => {
  it('posts explicitly with CSRF and displays the backend decision as inert text', async () => {
    const fetcher = mount()
    await screen.findByText(/Enabled hash engines/)
    expect(fetcher).toHaveBeenCalledTimes(1)
    await userEvent.type(screen.getByLabelText('SHA-256'), 'a'.repeat(64))
    await userEvent.click(screen.getByRole('button', { name: 'Look up hash' }))
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
    const write = fetcher.mock.calls.find(([, options]) => options?.method === 'POST')!
    expect(write[1]?.headers).toMatchObject({ 'X-CSRF-Token': 'csrf' })
    expect(JSON.parse(String(write[1]?.body))).toEqual({ sha256: 'a'.repeat(64) })
    await userEvent.clear(screen.getByLabelText('SHA-256'))
    expect(screen.queryByRole('region', { name: 'Hash lookup result' })).toBeNull()
  })
  it('does not retry failures or display an allow decision', async () => {
    const fetcher = mount(true)
    await screen.findByText(/Enabled hash engines/)
    await userEvent.type(screen.getByLabelText('SHA-256'), 'a'.repeat(64))
    await userEvent.click(screen.getByRole('button', { name: 'Look up hash' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('consumed quota')
    expect(screen.queryByRole('region', { name: 'Hash lookup result' })).toBeNull()
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1)
  })
})
