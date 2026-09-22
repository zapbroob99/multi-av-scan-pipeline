import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import Management from './automation-management'

function mount(role = 'admin', failure = false) {
  const fetcher = vi.fn(async (_url: string, options?: RequestInit) => options?.method === 'DELETE'
    ? failure ? new Response(JSON.stringify({ detail: 'Unavailable' }), { status: 503 })
      : new Response(JSON.stringify({ scan_id: 42, status: 'deleted', sample_removed: false }))
    : new Response(JSON.stringify({ id: 42, filename: 'automation.bin', source: 'api', service_client_id: 3,
      status: 'completed', attempt_count: 2, job_revision: 19 })))
  vi.stubGlobal('fetch', fetcher)
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter initialEntries={['/scans/42']}><Routes>
    <Route path="/scans/:scanId" element={<Management session={{ user: { id: 1, username: 'operator', role }, csrf_token: 'csrf' }} />} />
  </Routes></MemoryRouter></QueryClientProvider>)
  return fetcher
}

describe('Automation deletion', () => {
  it('requires confirmation and submits displayed attempt/revision, reporting cleanup separately', async () => {
    const fetcher = mount()
    await userEvent.click(await screen.findByRole('button', { name: 'Delete scan' }))
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(fetcher.mock.calls.filter(([, o]) => o?.method === 'DELETE')).toHaveLength(0)
    await userEvent.click(screen.getByRole('button', { name: 'Delete scan' }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm deletion' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Sample cleanup was not confirmed')
    const call = fetcher.mock.calls.find(([, o]) => o?.method === 'DELETE')!
    expect(call[0]).toBe('/api/ui/v1/api-ledger/scans/42')
    expect(JSON.parse(String(call[1]?.body))).toEqual({ attempt: 2, job_revision: 19 })
    expect(call[1]?.headers).toMatchObject({ 'X-CSRF-Token': 'csrf' })
    expect(screen.queryByRole('button', { name: 'Delete scan' })).toBeNull()
  })
  it('does not replay uncertain writes and requires refresh', async () => {
    const fetcher = mount('admin', true)
    await userEvent.click(await screen.findByRole('button', { name: 'Delete scan' }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm deletion' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Refresh and reconcile')
    expect(screen.queryByRole('button', { name: 'Delete scan' })).toBeNull()
    expect(fetcher.mock.calls.filter(([, o]) => o?.method === 'DELETE')).toHaveLength(1)
  })
  it('keeps analysts read-only', async () => {
    mount('analyst')
    await screen.findByText('Administrator access is required to delete scans.')
    expect(screen.queryByRole('button', { name: 'Delete scan' })).toBeNull()
  })
})
