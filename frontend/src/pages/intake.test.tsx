import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import Intake, { age } from './intake'

const WORKER = { at: 1790000000, age_seconds: 20, stale: false, ok: true, error: null, accepted: 3, duplicates: 1, rejected: 1,
  poll_seconds: 15, backend_key: 'drive', client_key: 'drive-storage', root_prefix: 'uploads', date_layout: '%Y/%m/%d',
  lookback_days: 3, batch_limit: 200 }
const EMPTY_QUEUE = { pending: 0, retrying: 0, claimed: 0, queued: 0, oldest_pending_at: null, oldest_pending_age_seconds: null }

function mount(overrides: Record<string, unknown> = {}) {
  const body = { manifest_worker: WORKER, manifest_record_invalid: false, queue: EMPTY_QUEUE, rejections: [], rejections_total: 0,
    failures: [], failures_truncated: false, ...overrides }
  const fetcher = vi.fn(async () => new Response(JSON.stringify(body)))
  vi.stubGlobal('fetch', fetcher)
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter><Intake /></MemoryRouter></QueryClientProvider>)
  return fetcher
}

describe('age', () => {
  it('rounds to a readable unit', () => {
    expect([age(45), age(600), age(7200), age(3 * 86400)]).toEqual(['45 s', '10 min', '2 h', '3 d'])
  })
})

describe('Deferred intake', () => {
  it('shows a healthy worker with the configuration it reported, without polling', async () => {
    const fetcher = mount()
    await screen.findByText('3 accepted · 1 already known · 1 rejected')
    expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/system/intake', expect.anything())
    expect(screen.queryByRole('alert')).toBeNull()
    expect(screen.getByText('drive-storage')).toBeInTheDocument()
    expect(screen.getByText('Nothing waiting')).toBeInTheDocument()
    await new Promise(resolve => setTimeout(resolve, 60))
    expect(fetcher).toHaveBeenCalledTimes(1)
    await userEvent.click(screen.getByRole('button', { name: 'Refresh intake' }))
    expect(fetcher).toHaveBeenCalledTimes(2)
  })

  it('warns about a stale or failing worker instead of presenting it as healthy', async () => {
    mount({ manifest_worker: { ...WORKER, stale: true, ok: false, age_seconds: 7200, error: "OSError: I/O error: '<path>'" } })
    const alerts = await screen.findAllByRole('alert')
    expect(alerts.map(alert => alert.textContent).join(' ')).toMatch(/2 h ago.*stopped or is stuck/)
    expect(alerts.map(alert => alert.textContent).join(' ')).toContain("The last cycle failed: OSError: I/O error: '<path>'")
  })

  it('distinguishes an unrecorded worker from an unreadable record', async () => {
    mount({ manifest_worker: null })
    expect(await screen.findByText(/No manifest intake cycle has been recorded/)).toBeInTheDocument()
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('flags an unreadable worker record', async () => {
    mount({ manifest_worker: null, manifest_record_invalid: true })
    expect(await screen.findByRole('alert')).toHaveTextContent('unreadable')
  })

  it('renders backlog, rejections and failures as inert bounded text', async () => {
    mount({
      queue: { pending: 4, retrying: 1, claimed: 1, queued: 2, oldest_pending_at: '2026-09-20T10:00:00+00:00', oldest_pending_age_seconds: 3 * 86400 },
      rejections: [{ backend_key: 'drive', manifest_object_id: 'uploads/<b>x</b>.json', reason: '<script>bad</script>',
        first_seen_at: 1790000000, last_seen_at: 1790000600, occurrences: 4 }],
      rejections_total: 60,
      failures: [{ id: 9, service_client_id: 2, client_name: 'Drive storage', client_request_id: 'u-9', backend_key: 'drive',
        object_id: 'uploads/u-9.pdf', original_filename: 'u-9.pdf', last_error: "Permission denied: '<path>'", attempt_count: 1,
        updated_at: '2026-09-23 10:00:00' }],
      failures_truncated: true,
    })
    expect(await screen.findByText('4 (1 retrying after an error)')).toBeInTheDocument()
    expect(screen.getByText(/3 d \(since 2026-09-20/)).toBeInTheDocument()
    expect(screen.getByText(/60 recorded, newest 1 shown/)).toBeInTheDocument()
    const rejections = screen.getByRole('region', { name: 'Rejected manifests table' })
    expect(within(rejections).getByText('<script>bad</script>')).toBeInTheDocument()
    expect(document.querySelector('td script, td b')).toBeNull()
    expect(screen.getByText("Permission denied: '<path>'")).toBeInTheDocument()
    expect(screen.getByText('Only the newest 1 failures are shown.')).toBeInTheDocument()
  })

  it('reports a read failure instead of an empty intake', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ detail: 'Budget exceeded' }), { status: 503 })))
    render(<QueryClientProvider client={new QueryClient()}><MemoryRouter><Intake /></MemoryRouter></QueryClientProvider>)
    expect(await screen.findByRole('alert')).toHaveTextContent('Budget exceeded')
    expect(screen.queryByText('Nothing waiting')).toBeNull()
  })
})
