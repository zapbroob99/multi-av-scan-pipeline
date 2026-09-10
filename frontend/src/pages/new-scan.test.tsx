import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import NewScan from './new-scan'

function mount({ limit = 1000, engines = 1, fail = false } = {}) {
  const fetcher = vi.fn(async (url: string) => {
    if (url.endsWith('/options')) return new Response(JSON.stringify({ file_max_bytes: limit,
      body_max_bytes: 10000, enabled_engine_count: engines, archive_mode: 'lazy_extract_on_detection' }))
    if (fail) throw new TypeError('Network unavailable')
    return new Response(JSON.stringify({ scan_id: 42, status: 'accepted', report_url: '/scans/42' }), { status: 202 })
  })
  vi.stubGlobal('fetch', fetcher)
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={client}><MemoryRouter><NewScan session={{
    user: { id: 1, username: 'analyst', role: 'analyst' }, csrf_token: 'session-csrf',
  }} /></MemoryRouter></QueryClientProvider>)
  return fetcher
}

describe('Scan submission', () => {
  // jsdom file-input validity is not updated by user-event's FileList shim.
  // Submit handlers are exercised directly here; Edge covers native submission.
  it('sends multipart with CSRF and shows acceptance, not completion', async () => {
    const fetcher = mount()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Create scan' })).toBeEnabled())
    await userEvent.upload(screen.getByLabelText('Sample file'), new File(['benign'], 'safe.txt'))
    await userEvent.type(screen.getByLabelText('Case name'), 'IR-001')
    fireEvent.submit(screen.getByLabelText('Sample file').closest('form')!)
    expect(await screen.findByRole('heading', { name: 'Scan accepted' })).toBeInTheDocument()
    expect(screen.getByText(/not a completed scan or a clean verdict/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open scan report' })).toHaveAttribute('href', '/scans/42')
    const call = vi.mocked(fetch).mock.calls.find(([url]) => url === '/api/ui/v1/scans')!
    const request = call[1]!
    expect(request.body).toBeInstanceOf(FormData)
    expect((request.body as FormData).get('case_name')).toBe('IR-001')
    expect(new Headers(request.headers).get('X-CSRF-Token')).toBe('session-csrf')
    expect(new Headers(request.headers).has('Content-Type')).toBe(false)
    expect(fetcher.mock.calls.filter(([url]) => url.endsWith('/scans'))).toHaveLength(1)
    await userEvent.click(screen.getByRole('button', { name: 'Submit another sample' }))
    expect(screen.getByLabelText('Sample file')).toHaveValue('')
  })
  it('rejects oversized files before any upload request', async () => {
    const fetcher = mount({ limit: 3 })
    await waitFor(() => expect(screen.getByRole('button', { name: 'Create scan' })).toBeEnabled())
    await userEvent.upload(screen.getByLabelText('Sample file'), new File(['too large'], 'safe.txt'))
    fireEvent.submit(screen.getByLabelText('Sample file').closest('form')!)
    expect(await screen.findByRole('alert')).toHaveTextContent('No upload was sent')
    expect(fetcher.mock.calls.filter(([url]) => url.endsWith('/scans'))).toHaveLength(0)
  })
  it('preserves form and warns about uncertain acceptance without retrying', async () => {
    const fetcher = mount({ fail: true })
    await waitFor(() => expect(screen.getByRole('button', { name: 'Create scan' })).toBeEnabled())
    await userEvent.upload(screen.getByLabelText('Sample file'), new File(['benign'], 'safe.txt'))
    await userEvent.type(screen.getByLabelText('Analyst note'), 'Keep this context')
    fireEvent.submit(screen.getByLabelText('Sample file').closest('form')!)
    expect(await screen.findByRole('alert')).toHaveTextContent('Check Dashboard before retrying')
    expect(screen.getByLabelText('Analyst note')).toHaveValue('Keep this context')
    expect(fetcher.mock.calls.filter(([url]) => url.endsWith('/scans'))).toHaveLength(1)
  })
  it('does not allow submission when no file engines are enabled', async () => {
    mount({ engines: 0 })
    expect(await screen.findByText(/No eligible engines are enabled/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Create scan' })).toBeDisabled()
  })
  it('disables repeat submission while acceptance is pending', async () => {
    const fetcher = mount()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Create scan' })).toBeEnabled())
    let finish!: (response: Response) => void
    fetcher.mockImplementationOnce(() => new Promise<Response>(resolve => { finish = resolve }))
    await userEvent.upload(screen.getByLabelText('Sample file'), new File(['benign'], 'safe.txt'))
    fireEvent.submit(screen.getByLabelText('Sample file').closest('form')!)
    await waitFor(() => expect(screen.getByRole('button', { name: 'Sending sample…' })).toBeDisabled())
    expect(screen.getByLabelText('Sample file')).toBeDisabled()
    fireEvent.submit(screen.getByLabelText('Sample file').closest('form')!)
    expect(fetcher.mock.calls.filter(([url]) => url.endsWith('/scans'))).toHaveLength(1)
    finish(new Response(JSON.stringify({ scan_id: 42, status: 'accepted', report_url: '/scans/42' }), { status: 202 }))
    await screen.findByRole('heading', { name: 'Scan accepted' })
  })
})
