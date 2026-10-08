import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import ApiLedger from './api-ledger'
import type { Session } from '../lib/api'

const ADMIN = { csrf_token: 'csrf', user: { id: 1, username: 'admin', role: 'admin' } } as unknown as Session

/** History reads and writes; the client filter's name list is a separate read. */
function ledgerCalls(fetcher: { mock: { calls: unknown[][] } }) {
  return fetcher.mock.calls.filter(([url]) => !String(url).includes('/api-ledger/clients'))
}

function mount(extra: object = {}, session?: Session) {
  const fetcher = vi.fn(async (_url: string, init?: RequestInit) => init?.method === 'POST' ? new Response(JSON.stringify({ id: 11 }), { status: 201 })
    : new Response(JSON.stringify({ items: [{ id: 42, filename: '<script>API sample</script>',
    sha256: 'a'.repeat(64), size_bytes: 1024, case_name: 'Case', source: 'icap', service_client_id: 7,
    client_name: 'Integration', batch_id: 3, status: 'completed', risk_score: 0, risk_level: 'info', created_at: '2026-09-17', ...extra }], next_before: 42 })))
  vi.stubGlobal('fetch', fetcher)
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter><ApiLedger session={session} /></MemoryRouter></QueryClientProvider>)
  return fetcher
}

describe('API ledger', () => {
  it('lets administrators add an exception from a flagged row, scoped to its client by default', async () => {
    const fetcher = mount({ risk_level: 'critical', risk_score: 90 }, ADMIN)
    await userEvent.click(await screen.findByRole('button', { name: 'Add exception for scan 42' }))
    const dialog = await screen.findByRole('dialog')
    expect(dialog).toHaveTextContent('a'.repeat(64))
    expect(within(dialog).getByLabelText('Applies to')).toHaveDisplayValue('Only #7 Integration')
    await userEvent.selectOptions(within(dialog).getByLabelText('Expires'), '90')
    await userEvent.type(within(dialog).getByLabelText('Reason'), 'Ticket 7')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Add exception' }))
    await waitFor(() => expect(fetcher.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(true))
    const [, init] = fetcher.mock.calls.find(([, call]) => call?.method === 'POST')!
    expect(JSON.parse(String(init!.body))).toEqual({ sha256: 'a'.repeat(64), reason: 'Ticket 7', service_client_id: 7, expires_in_days: 90 })
    expect(await screen.findByText(/Exception #11 added/)).toBeInTheDocument()
  })
  it('offers no exception for a clean row', async () => {
    mount({}, ADMIN)
    await screen.findByRole('link', { name: '<script>API sample</script>' })
    expect(screen.queryByRole('button', { name: /Add exception/ })).toBeNull()
  })
  it('offers no exception once one let the file through', async () => {
    mount({ risk_level: 'critical', risk_score: 90, exception_id: 4 }, ADMIN)
    await screen.findByRole('link', { name: '<script>API sample</script>' })
    expect(screen.queryByRole('button', { name: /Add exception/ })).toBeNull()
  })
  it('offers analysts no exception', async () => {
    mount({ risk_level: 'critical', risk_score: 90 })
    await screen.findByRole('link', { name: '<script>API sample</script>' })
    expect(screen.queryByRole('button', { name: /Add exception/ })).toBeNull()
  })
  it('renders inert previews with honest risk labels and compatible report links', async () => {
    mount()
    await screen.findByRole('link', { name: '<script>API sample</script>' })
    expect(document.querySelector('script')).toBeNull()
    expect(screen.getByText(/Recorded risk is not a clean verdict/)).toBeVisible()
    expect(screen.getAllByRole('link', { name: 'Report' })[0]).toHaveAttribute('href', '/api-ledger/scans/42')
    expect(screen.getByRole('link', { name: 'Batch' })).toHaveAttribute('href', '/api-ledger/batches/3')
  })
  it('shows a refused file as not allowed beside its recorded risk, never as malware', async () => {
    const fetcher = mount({ not_allowed: 'archive_refused', not_allowed_label: 'Archive' })
    await screen.findByRole('link', { name: '<script>API sample</script>' })
    const row = screen.getByRole('link', { name: '<script>API sample</script>' }).closest('tr')!
    expect(row).toHaveTextContent('No detection')
    expect(row).toHaveTextContent('Not allowedArchive')
    expect(row).not.toHaveClass('row-alert')
    await userEvent.selectOptions(screen.getByLabelText('Recorded risk'), 'not_allowed')
    await userEvent.click(screen.getByRole('button', { name: 'Apply filters' }))
    expect(ledgerCalls(fetcher).at(-1)?.[0]).toBe('/api/ui/v1/api-ledger?risk=not_allowed&limit=20')
  })
  it('preserves scoped filters across seek pages and supports unassigned ownership', async () => {
    const fetcher = mount()
    await screen.findByRole('link', { name: '<script>API sample</script>' })
    await userEvent.click(screen.getByRole('button', { name: 'Filter client #7' }))
    expect(fetcher.mock.lastCall?.[0]).toBe('/api/ui/v1/api-ledger?client_id=7&limit=20')
    await userEvent.click(screen.getByRole('button', { name: 'Older scans' }))
    expect(fetcher.mock.lastCall?.[0]).toBe('/api/ui/v1/api-ledger?client_id=7&before=42&limit=20')
    await userEvent.click(screen.getByRole('checkbox'))
    await userEvent.click(screen.getByRole('button', { name: 'Apply filters' }))
    expect(fetcher.mock.lastCall?.[0]).toBe('/api/ui/v1/api-ledger?unassigned=true&limit=20')
  })
  it('hides cached history after a failed refresh without retry', async () => {
    const fetcher = mount()
    await screen.findByRole('link', { name: '<script>API sample</script>' })
    fetcher.mockImplementation(async () => new Response(JSON.stringify({ detail: 'Read budget exceeded' }), { status: 503 }))
    await userEvent.click(screen.getByRole('button', { name: 'Refresh ledger' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Read budget exceeded')
    expect(screen.queryByRole('link', { name: 'Report' })).toBeNull()
    expect(ledgerCalls(fetcher)).toHaveLength(2)
  })
})
