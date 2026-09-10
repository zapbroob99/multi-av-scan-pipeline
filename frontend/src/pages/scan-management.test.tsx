import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import ScanManagement from './scan-management'

function mount({ role = 'admin', status = 'completed' } = {}) {
  const scan = { id: 42, filename: '<script>sample</script>', status, attempt_count: 3, job_revision: 9 }
  const fetcher = vi.fn(async (_url: string, options?: RequestInit) => new Response(JSON.stringify(
    options?.method === 'POST' ? { scan_id: 42, status: 'accepted' }
      : options?.method === 'DELETE' ? { scan_id: 42, status: 'deleted', sample_removed: false } : scan)))
  vi.stubGlobal('fetch', fetcher)
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/scans/42/manage']}><Routes>
    <Route path="/scans/:scanId/manage" element={<ScanManagement session={{ user: { id: 1, username: 'user', role }, csrf_token: 'csrf' }} />} />
  </Routes></MemoryRouter></QueryClientProvider>)
  return { fetcher, client }
}

describe('Scan management', () => {
  it('requires confirmation and submits the displayed attempt and job revision once', async () => {
    const { fetcher } = mount({ role: 'analyst' })
    await screen.findByRole('heading', { name: '<script>sample</script>' })
    expect(document.querySelector('script')).toBeNull()
    expect(screen.queryByRole('button', { name: 'Delete scan' })).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Retry scan' }))
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0)
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    await userEvent.click(screen.getByRole('button', { name: 'Retry scan' }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    await screen.findByText(/Retry accepted/)
    const writes = fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')
    expect(writes).toHaveLength(1)
    expect(JSON.parse(String(writes[0][1]?.body))).toEqual({ attempt: 3, job_revision: 9 })
    expect(writes[0][1]?.headers).toMatchObject({ 'X-CSRF-Token': 'csrf' })
    expect(screen.queryByRole('button', { name: 'Retry scan' })).toBeNull()
  })
  it('blocks active scans including finalizing', async () => {
    mount({ status: 'finalizing' })
    expect(await screen.findByRole('button', { name: 'Retry scan' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Delete scan' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Download summary JSON' })).toBeEnabled()
  })
  it('reports record deletion separately from unconfirmed sample cleanup', async () => {
    mount()
    await userEvent.click(await screen.findByRole('button', { name: 'Delete scan' }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    await screen.findByText(/Scan record deleted.*Sample file removal was not confirmed/)
    expect(screen.queryByRole('link', { name: 'Back to report' })).toBeNull()
  })
  it('does not replay an ambiguous mutation failure and clears stale report data', async () => {
    const { fetcher, client } = mount()
    await userEvent.click(await screen.findByRole('button', { name: 'Retry scan' }))
    fetcher.mockImplementation(async (_url, options) => new Response(JSON.stringify({ detail: 'Temporarily unavailable' }), { status: options?.method === 'POST' ? 503 : 404 }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    await screen.findByText(/request may have reached the server/)
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Retry scan' })).toBeNull())
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1)
    expect(client.getQueryData(['scan-report', '42'])).toBeUndefined()
  })
  it('downloads server-produced summary and full exports only on demand', async () => {
    const { fetcher } = mount()
    await screen.findByRole('heading', { name: '<script>sample</script>' })
    expect(fetcher.mock.calls.some(([url]) => url.includes('summary-export'))).toBe(false)
    const create = vi.fn(() => 'blob:test')
    vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: create, revokeObjectURL: vi.fn() }))
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    fetcher.mockImplementationOnce(async () => new Response(JSON.stringify({ filename: 'masp-scan-42-summary.csv', media_type: 'text/csv', content: 'field,value\r\nreport.decision,null\r\n' })))
    await userEvent.click(screen.getByRole('button', { name: 'Download summary CSV' }))
    await waitFor(() => expect(click).toHaveBeenCalledOnce())
    expect(fetcher.mock.calls.at(-1)?.[0]).toBe('/api/ui/v1/scans/42/summary-export?format=csv')
    expect(create).toHaveBeenCalledOnce()
    fetcher.mockImplementationOnce(async () => new Response(JSON.stringify({ filename: 'masp-scan-42-full.json', media_type: 'application/json', content: '{"engine_results":[]}' })))
    await userEvent.click(screen.getByRole('button', { name: 'Download full JSON' }))
    await waitFor(() => expect(click).toHaveBeenCalledTimes(2))
    expect(fetcher.mock.calls.at(-1)?.[0]).toBe('/api/ui/v1/scans/42/export?format=json')
    click.mockRestore()
  })
})
