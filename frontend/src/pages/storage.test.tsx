import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import Storage from './storage'
import StorageLocation from './storage-location'
import StorageFindings from './storage-findings'
import StorageLocationForm, { rulesToPolicy } from './storage-location-form'

const ADMIN = { user: { id: 1, username: 'admin', role: 'admin' }, csrf_token: 'csrf' }
const ANALYST = { user: { id: 2, username: 'analyst', role: 'analyst' }, csrf_token: 'csrf' }
const COUNTS = { waiting: 2, changed: 1, light_passed: 40, light_detected: 3, full_pending: 5, unreadable: 1, removed: 0 }
const POLICY = { default_tier: 'light', tier_rules: [{ pattern: 'bulk/*', min_bytes: null, max_bytes: null, tier: 'light' }],
  type_policy: { mode: 'denylist', families: ['executable', 'script'] }, archive_action: 'full',
  hash_check: { enabled: true, max_bytes: 10 * 1024 ** 3 }, ignore_patterns: ['*.tmp'], stability_seconds: 60,
  crawl_interval_seconds: 300, crawl_entries_per_cycle: 5000, inspections_per_cycle: 500 }
const LOCATION = { id: 4, name: 'Finance uploads', enabled: true, mode: 'crawl', backend_key: 'share', prefix: 'finance',
  client: { id: 2, name: 'Drive' }, profile: { id: 3, name: 'Default' }, policy_revision: 2, management_revision: 5, counts: COUNTS,
  detected_findings: 4, last_cycle: { at: 1790000000, age_seconds: 30, ok: true, error: null, pass_id: 9, pass_completed: false, crawled: 100,
    new: 3, changed: 0, removed: 0, inspected: 10, findings: 1, directory_errors: 0, errors: [] }, last_cycle_invalid: false,
  last_completed_pass: null, current_pass: null }
const WORKER = { at: 1790000000, age_seconds: 20, stale: false, ok: true, error: null, poll_seconds: 10, locations: 1,
  worker_id: 'storage-host-1', backends: ['share'] }

function stub(routes: Record<string, unknown>) {
  const fetcher = vi.fn(async (url: string, options?: RequestInit) => {
    if (options?.method && options.method !== 'GET') return new Response(JSON.stringify({ id: 11 }), { status: 201 })
    const path = url.split('?')[0]
    const body = routes[path]
    return body === undefined ? new Response(JSON.stringify({ detail: 'missing' }), { status: 404 }) : new Response(JSON.stringify(body))
  })
  vi.stubGlobal('fetch', fetcher)
  return fetcher
}

function renderAt(path: string, element: React.ReactNode, pattern = '*') {
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter initialEntries={[path]}>
    <Routes><Route path={pattern} element={element} /><Route path="*" element={<p>navigated</p>} /></Routes>
  </MemoryRouter></QueryClientProvider>)
}

describe('Folder scanning overview', () => {
  it('shows coverage without calling type-checked files clean', async () => {
    stub({ '/api/ui/v1/storage/overview': { worker: WORKER, worker_record_invalid: false, locations: [LOCATION], locations_truncated: false } })
    renderAt('/storage', <Storage session={ADMIN} />)
    const table = await screen.findByRole('region', { name: 'Protected locations' })
    expect(within(table).getByText('Finance uploads')).toBeInTheDocument()
    expect(within(table).getByText('40')).toBeInTheDocument()
    expect(document.querySelector('.callout')).toHaveTextContent(/type check was not scanned by an antivirus engine/)
    expect(screen.queryByText(/clean/i)).toBeNull()
    expect(screen.getByRole('link', { name: 'New location' })).toBeInTheDocument()
  })

  it('warns about a stale worker and hides management from analysts', async () => {
    stub({ '/api/ui/v1/storage/overview': { worker: { ...WORKER, stale: true, age_seconds: 7200 }, worker_record_invalid: false,
      locations: [{ ...LOCATION, last_cycle: null }], locations_truncated: false } })
    renderAt('/storage', <Storage session={ANALYST} />)
    expect((await screen.findAllByRole('alert'))[0]).toHaveTextContent(/2 h ago.*stopped or is stuck/)
    expect(screen.getByText('No cycle has run for this location yet.')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'New location' })).toBeNull()
  })
})

describe('Location detail', () => {
  it('lists files with their state and renders paths as inert text', async () => {
    stub({ '/api/ui/v1/storage/locations/4': { ...LOCATION, policy: POLICY, policy_invalid: false },
      '/api/ui/v1/storage/locations/4/objects': { items: [{ id: 8, object_id: 'finance/<b>x</b>.exe', size_bytes: 2048,
        state: 'light_detected', tier: 'light', detected_type: 'pe', families: ['executable'], sha256: 'a'.repeat(64), hash_list_kind: null,
        finding_count: 1, policy_revision: 2, first_seen_at: 1790000000, last_changed_at: 1790000000, processed_at: 1790000060,
        last_error: null }], next_before: null } })
    renderAt('/storage/locations/4', <StorageLocation session={ANALYST} />, '/storage/locations/:locationId')
    const files = await screen.findByRole('region', { name: 'Files' })
    expect(within(files).getByText('finance/<b>x</b>.exe')).toBeInTheDocument()
    expect(document.querySelector('td b')).toBeNull()
    expect(within(files).getByText('Detected by light inspection')).toBeInTheDocument()
    expect(screen.getByText(/not a clean antivirus result/)).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Edit location' })).toBeNull()
  })
})

describe('Findings', () => {
  it('passes filters to the server and marks review-only findings', async () => {
    const fetcher = stub({ '/api/ui/v1/storage/findings': { items: [{ id: 3, location: { id: 4, name: 'Finance uploads' },
      storage_object_id: 8, object_id: 'finance/photo.png', object_state: 'light_passed', sha256: null, kind: 'type_mismatch',
      severity: 'medium', detected: false, title: 'Declared .png content is actually pdf', detail: {}, policy_revision: 2,
      created_at: 1790000000 }], next_before: null } })
    renderAt('/storage/findings?kind=type_mismatch', <StorageFindings />)
    expect(await screen.findByText('review only')).toBeInTheDocument()
    expect(fetcher.mock.calls[0][0]).toContain('kind=type_mismatch')
  })
})

describe('Location form', () => {
  it('converts tier rule sizes from MiB and leaves blanks unbounded', () => {
    expect(rulesToPolicy([{ pattern: ' big/* ', min: '100', max: '', tier: 'light' }, { pattern: '', min: '', max: '', tier: 'full' }]))
      .toEqual([{ pattern: 'big/*', min_bytes: 100 * 1024 * 1024, max_bytes: null, tier: 'light' }])
  })

  it('creates a location only after confirmation', async () => {
    const fetcher = stub({ '/api/ui/v1/storage/options': { backends: ['share'], clients_truncated: false,
      families: ['executable', 'script', 'archive', 'office', 'pdf', 'image', 'markup', 'unrecognized'], default_policy: POLICY,
      clients: [{ id: 2, name: 'Drive', client_key: 'drive', enabled: true, profiles: [{ id: 3, name: 'Default', enabled: true }] }] } })
    renderAt('/storage/locations/new', <StorageLocationForm session={ADMIN} />, '/storage/locations/new')
    await userEvent.type(await screen.findByLabelText('Name'), 'Finance uploads')
    await userEvent.selectOptions(screen.getByLabelText('Service client'), '2')
    await userEvent.selectOptions(screen.getByLabelText('Scan profile'), '3')
    await userEvent.selectOptions(screen.getByLabelText('Storage backend'), 'share')
    await userEvent.type(screen.getByLabelText('Prefix inside the backend'), 'finance')
    await userEvent.click(screen.getByRole('button', { name: 'Review' }))
    expect(fetcher.mock.calls.filter(([, o]) => o?.method === 'POST')).toHaveLength(0)
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Confirm' }))
    expect(await screen.findByText('navigated')).toBeInTheDocument()
    const [url, options] = fetcher.mock.calls.find(([, o]) => o?.method === 'POST')!
    expect(url).toBe('/api/ui/v1/storage/locations')
    const body = JSON.parse(String(options?.body))
    expect(body).toMatchObject({ name: 'Finance uploads', service_client_id: 2, scan_profile_id: 3, backend_key: 'share',
      prefix: 'finance', mode: 'crawl', enabled: true })
    expect(body.policy.default_tier).toBe('light')
    expect(body.policy.type_policy).toEqual({ mode: 'denylist', families: ['executable', 'script'] })
    expect(options?.headers).toMatchObject({ 'X-CSRF-Token': 'csrf' })
  })

  it('refuses an allowlist without families before sending anything', async () => {
    const fetcher = stub({ '/api/ui/v1/storage/options': { backends: ['share'], clients_truncated: false, families: ['executable', 'script'],
      default_policy: POLICY, clients: [{ id: 2, name: 'Drive', client_key: 'drive', enabled: true, profiles: [{ id: 3, name: 'Default', enabled: true }] }] } })
    renderAt('/storage/locations/new', <StorageLocationForm session={ADMIN} />, '/storage/locations/new')
    await userEvent.type(await screen.findByLabelText('Name'), 'Strict')
    await userEvent.selectOptions(screen.getByLabelText('Service client'), '2')
    await userEvent.selectOptions(screen.getByLabelText('Scan profile'), '3')
    await userEvent.selectOptions(screen.getByLabelText('Storage backend'), 'share')
    await userEvent.selectOptions(screen.getByLabelText('Type policy'), 'allowlist')
    await userEvent.click(screen.getByLabelText(/Executables/))
    await userEvent.click(screen.getByLabelText(/Scripts/))
    await userEvent.click(screen.getByRole('button', { name: 'Review' }))
    expect(screen.getByRole('alert')).toHaveTextContent('Choose at least one family')
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(fetcher.mock.calls.filter(([, o]) => o?.method === 'POST')).toHaveLength(0)
  })
})
