import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import Delivery from './delivery'

const SESSION = { user: { id: 1, username: 'admin', role: 'admin' }, csrf_token: 'csrf' }
const VIEW = {
  generated_at: '2026-09-28T07:00:00+00:00',
  gateways: [{ key: 'storage:1344', client_key: 'storage', service_name: 'masp', port: 1344, fail_closed: true, block_on_review: true,
    allowlist_entries: 2, started_at: 1790000000, at: 1790000100, age_seconds: 400, stale: true,
    block_archives: true, max_bytes: 104857600, wait_seconds: 30,
    counters: { requests: 12, allowed: 10, blocked: 2, fail_actions: 0, errors: 0, connections_rejected: 1 }, last_request_at: 1790000090,
    events: [{ at: 1790000050, kind: 'rejected', detail: 'Connection refused: source is not in MASP_ICAP_ALLOWED_IPS', peer: '10.0.0.9', scan_id: null },
      { at: 1790000040, kind: 'blocked', detail: 'Blocked by scan decision', peer: null, scan_id: 42 }],
    binding: 'client', client_id: 7, client_name: 'Storage gateway', binding_detail: null }],
  notifications: { pending: 2, delivering: 0, delivered: 5, retrying: 1, oldest_pending_at: '2026-09-28 06:00:00', last_delivered_at: null,
    failures: [{ id: 3, scan_job_id: 77, client_name: 'Drive', event_type: 'malware.detected', attempt_count: 4,
      last_error: 'SIEM webhook returned HTTP 503.', next_attempt_at: 1790003600, created_at: '2026-09-28 06:00:00' }] },
}

describe('ICAP and SIEM', () => {
  it('shows a silent gateway, its events and failed notifications, and retries only after confirmation', async () => {
    const fetcher = vi.fn(async (_url: string, options?: RequestInit) =>
      new Response(JSON.stringify(options?.method === 'POST' ? { rescheduled: 1 } : VIEW)))
    vi.stubGlobal('fetch', fetcher)
    render(<QueryClientProvider client={new QueryClient()}><MemoryRouter><Delivery session={SESSION} /></MemoryRouter></QueryClientProvider>)
    expect(await screen.findByText(/No report for 7 min/)).toBeInTheDocument()
    const events = screen.getByRole('region', { name: 'Recent ICAP events for storage' })
    expect(within(events).getByText('Refused source')).toBeInTheDocument()
    expect(within(events).getByText('Source 10.0.0.9')).toBeInTheDocument()
    expect(within(events).getByRole('link', { name: 'Scan #42' })).toHaveAttribute('href', '/api-ledger/scans/42')
    expect(screen.getByText('Refuses archives unless a profile checks them · size limit 100 MiB · waits up to 30 s')).toBeInTheDocument()
    expect(screen.getByText('SIEM webhook returned HTTP 503.')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Retry failed now' }))
    expect(fetcher.mock.calls.filter(([, o]) => o?.method === 'POST')).toHaveLength(0)
    await userEvent.click(screen.getByRole('button', { name: 'Retry now' }))
    expect(await screen.findByText('1 notification(s) will be attempted on the next delivery cycle.')).toBeInTheDocument()
    expect(fetcher.mock.calls.find(([, o]) => o?.method === 'POST')![0]).toBe('/api/ui/v1/system/notifications/retry')
  })

  it('names the client each gateway files scans under and explains a wrong binding', async () => {
    const gateway = { ...VIEW.gateways[0], stale: false, age_seconds: 10, events: [] }
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ ...VIEW, gateways: [
      gateway,
      { ...gateway, key: 'legacy-default:1345', client_key: 'legacy-default', port: 1345, binding: 'legacy_default',
        client_id: 1, client_name: 'Legacy API / ICAP', binding_detail: 'Scans are filed under the compatibility client.' },
      { ...gateway, key: 'typo:1346', client_key: 'typo', port: 1346, binding: 'unresolved', client_id: null, client_name: null,
        binding_detail: 'No service client has the key typo.' }] }))))
    render(<QueryClientProvider client={new QueryClient()}><MemoryRouter><Delivery session={SESSION} /></MemoryRouter></QueryClientProvider>)
    const bound = await screen.findByRole('article', { name: 'ICAP gateway storage' })
    expect(within(bound).getByRole('link', { name: /Storage gateway/ })).toHaveAttribute('href', '/service-clients/7/setup')
    expect(within(bound).queryByRole('alert')).not.toBeInTheDocument()
    const legacy = screen.getByRole('article', { name: 'ICAP gateway legacy-default' })
    expect(within(legacy).getByText(/filed under the compatibility/)).toBeInTheDocument()
    expect(within(legacy).getByRole('link', { name: /Legacy API \/ ICAP/ })).toHaveAttribute('href', '/service-clients/1/setup')
    const broken = screen.getByRole('article', { name: 'ICAP gateway typo' })
    expect(within(broken).getByRole('alert')).toHaveTextContent('No service client has the key typo. Every request through this gateway fails, so every upload is blocked.')
    expect(within(broken).queryByRole('link', { name: /typo/ })).not.toBeInTheDocument()
  })

  it('explains an empty deployment instead of showing blank cards', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ ...VIEW, gateways: [],
      notifications: { ...VIEW.notifications, pending: 0, delivered: 0, retrying: 0, failures: [], oldest_pending_at: null } }))))
    render(<QueryClientProvider client={new QueryClient()}><MemoryRouter><Delivery session={SESSION} /></MemoryRouter></QueryClientProvider>)
    expect(await screen.findByText(/No ICAP gateway has reported/)).toBeInTheDocument()
    expect(screen.getByText(/No notification has been produced/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Retry failed now' })).toBeDisabled()
  })
})
