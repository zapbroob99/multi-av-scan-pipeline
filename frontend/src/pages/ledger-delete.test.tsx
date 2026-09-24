import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { expect, it, vi } from 'vitest'
import ApiLedger from './api-ledger'

function mount(role = 'admin', failure = false) {
  const fetcher = vi.fn(async (_url: string, options?: RequestInit) => options?.method === 'DELETE'
    ? new Response(JSON.stringify(failure ? { detail: 'Uncertain request' } : {
      requested_count: 1, deleted_ids: [42], blocked_ids: [], cleanup_failed_ids: [42],
    }), { status: failure ? 503 : 200 })
    : new Response(JSON.stringify({ items: [{ id: 42, filename: 'automation.bin', source: 'api',
      sha256: 'b'.repeat(64), case_name: 'Case', client_name: null, created_at: '2026-09-17',
      size_bytes: 1, service_client_id: null, batch_id: null, status: 'completed',
      attempt_count: 2, job_revision: 19, risk_score: 0, risk_level: 'info' }], next_before: null })))
  vi.stubGlobal('fetch', fetcher)
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter>
    <ApiLedger session={{ user: { id: 1, username: 'operator', role }, csrf_token: 'csrf' }} />
  </MemoryRouter></QueryClientProvider>)
  return fetcher
}

it('keeps analyst history read-only', async () => {
  mount('analyst')
  await screen.findByText('automation.bin')
  expect(screen.queryByRole('checkbox', { name: 'Select scan 42' })).toBeNull()
  expect(screen.queryByRole('button', { name: /Delete selected/ })).toBeNull()
})

it.each([false, true])('sends confirmed fences once and requires fresh reads afterwards (failure=%s)', async failure => {
  const fetcher = mount('admin', failure)
  await userEvent.click(await screen.findByRole('checkbox', { name: 'Select scan 42' }))
  await userEvent.click(screen.getByRole('button', { name: 'Delete selected (1)' }))
  expect(fetcher).toHaveBeenCalledTimes(1)
  await userEvent.click(screen.getByRole('button', { name: 'Confirm deletion' }))
  if (failure) expect(await screen.findByRole('alert')).toHaveTextContent('may have partially completed')
  else expect(await screen.findByRole('status')).toHaveTextContent('File cleanup unconfirmed IDs: 42')
  const write = fetcher.mock.calls.find(([, options]) => options?.method === 'DELETE')!
  expect(write[0]).toBe('/api/ui/v1/api-ledger/scans')
  expect(JSON.parse(write[1]!.body as string)).toEqual({ scans: [{ scan_id: 42, attempt: 2, job_revision: 19 }] })
  expect(new Headers(write[1]!.headers).get('X-CSRF-Token')).toBe('csrf')
  expect(screen.queryByRole('checkbox', { name: 'Select scan 42' })).toBeNull()
  expect(screen.getByRole('button', { name: 'Delete selected (0)' })).toBeDisabled()
  expect(fetcher).toHaveBeenCalledTimes(2)
  await userEvent.click(screen.getByRole('button', { name: 'Refresh ledger' }))
  expect(await screen.findByRole('checkbox', { name: 'Select scan 42' })).not.toBeChecked()
  expect(fetcher).toHaveBeenCalledTimes(3)
})

it('selects the whole page from the header for admins', async () => {
  mount()
  await userEvent.click(await screen.findByRole('checkbox', { name: 'Select all on this page' }))
  expect(screen.getByRole('checkbox', { name: 'Select scan 42' })).toBeChecked()
  expect(screen.getByRole('button', { name: 'Delete selected (1)' })).toBeEnabled()
})
