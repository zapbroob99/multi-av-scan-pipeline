import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import ClientOverview from './client-overview'

const DATA = {
  client_id: 3, client_name: 'Integration', enabled: true, managed: false,
  profile: { id: 9, name: 'Default', enabled: true, is_default: true, management_revision: 2, incomplete: false,
    rules: { version: 2, inconclusive: 'block', rules: [{ when: {}, action: 'scan', engines: [1], archive: 'inspect' }] } },
  upload_policy_bytes: 0, upload_policy_source: 'Built-in default', http_body_ceiling_bytes: null, http_configuration_valid: false,
  gateways: [{ port: 1344, reported_at: 1700000000, stale: true, max_bytes: 52428800, wait_seconds: 30, fail_closed: true }], gateways_incomplete: false,
  engines: [{ id: 1, name: 'Scanner', eligible: true, pool_id: 7, pool_name: 'Windows', pool_enabled: false,
    observations: [{ node_id: 'node', online: true, lifecycle: 'draining', checked_at: 1700000000, check: 'stale' }], observations_incomplete: true }],
  observed_at: 1700000010, header_types: [],
}
function mount(fail = false) {
  const fetcher = vi.fn(async (url: string) => {
    if (url.includes('/configuration')) return new Response(JSON.stringify(fail ? { detail: 'Read unavailable' } : DATA), { status: fail ? 503 : 200 })
    if (url.includes('/profiles')) return new Response(JSON.stringify({ items: [{ id: 10, name: 'Named', enabled: true }], next_after: null }))
    return new Response(JSON.stringify({ methods: [{ key: 'api', label: 'REST API', summary: 'No active credential.' }] }))
  })
  vi.stubGlobal('fetch', fetcher)
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter initialEntries={['/service-clients/3/overview']}>
    <Routes><Route path="/service-clients/:clientId/overview" element={<ClientOverview session={{ user: { id: 1, username: 'admin', role: 'admin' }, csrf_token: 'csrf' }} />} /></Routes>
  </MemoryRouter></QueryClientProvider>)
  return fetcher
}

describe('Client configuration overview', () => {
  it('keeps admission errors, placement and historical health distinct with actionable links', async () => {
    mount()
    await screen.findByText('Invalid configuration — uploads refused')
    expect(screen.getByText('Placement: Windows — disabled or unavailable')).toBeInTheDocument()
    expect(screen.getByText('node', { exact: true }).parentElement).toHaveTextContent('draining · check: stale')
    expect(screen.getByText(/evidence is incomplete/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Edit profiles and rules' })).toHaveAttribute('href', '/policies/profiles/3')
    expect(screen.getByRole('link', { name: 'Edit upload policy' })).toHaveAttribute('href', '/scan-policy')
    expect(screen.queryByText('Healthy')).toBeNull()
  })
  it('restricts ICAP to the default profile and labels stale gateway evidence', async () => {
    const fetcher = mount()
    await screen.findByText('Invalid configuration — uploads refused')
    await userEvent.selectOptions(screen.getByLabelText('Profile'), '10')
    await vi.waitFor(() => expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/service-clients/3/configuration?profile_id=10', expect.anything()))
    await userEvent.selectOptions(screen.getByLabelText('Submission path'), 'icap')
    expect(screen.getByLabelText('Profile')).toBeDisabled()
    expect(screen.getByLabelText('Profile')).toHaveValue('')
    await screen.findByText(/Report stale/)
    expect(screen.getByText(/ICAP always uses/)).toBeInTheDocument()
  })
  it('does not invent a configuration when the read fails or replay the request', async () => {
    const fetcher = mount(true)
    expect(await screen.findByRole('alert')).toHaveTextContent('Read unavailable')
    expect(screen.queryByText('1. Connection')).toBeNull()
    expect(fetcher.mock.calls.filter(([url]) => url.includes('/configuration'))).toHaveLength(1)
  })
})
