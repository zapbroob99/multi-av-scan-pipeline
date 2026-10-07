import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import ClientSetup from './client-setup'

const READY = {
  client_id: 3, client_key: 'drive-gateway', display_name: 'Drive Gateway', enabled: true,
  managed: false, ready: true,
  checks: [
    { key: 'client_enabled', label: 'Client is enabled', passed: true, detail: 'Accepting submissions.' },
    { key: 'default_profile', label: 'Enabled default profile', passed: true, detail: 'Routing through Default routing.' },
    { key: 'assigned_engines', label: 'Profile has assigned engines', passed: true, detail: '2 engine instance(s) assigned.' },
    { key: 'eligible_engines', label: 'An assigned engine can run automation work', passed: true, detail: '1 of 2 assigned engine(s) are eligible for API and ICAP.' },
  ],
  methods: [
    { key: 'api', label: 'REST API', in_use: true, ready: true, summary: 'Ready for bearer-token submissions.',
      checks: [{ key: 'active_credential', label: 'Active API credential', passed: true, detail: '1 active credential(s).' }] },
    { key: 'icap', label: 'ICAP gateway', in_use: false, ready: false, summary: 'Not set up: no gateway uses this client key.',
      checks: [{ key: 'icap_gateway', label: 'An ICAP gateway is bound to this client', passed: false,
        detail: 'Set MASP_ICAP_SERVICE_CLIENT_KEY=drive-gateway on the gateway.' }] },
    { key: 'manifest', label: 'Manifest intake', in_use: false, ready: false, summary: 'Not set up.',
      checks: [{ key: 'manifest_worker', label: 'The manifest worker runs for this client', passed: false,
        detail: 'No manifest worker has run. Enable the manifest profile.' }] },
  ],
  profile_id: 9, profile_name: 'Default routing',
  engines: [
    { id: 1, display_name: 'Metadata', adapter_key: 'static_metadata', enabled: true, eligible: true, excluded_reason: null },
    { id: 2, display_name: 'VirusTotal', adapter_key: 'virustotal', enabled: true, eligible: false,
      excluded_reason: 'Paid reputation service: used for manual lookups only, never for API or ICAP files.' },
  ],
  eligible_engine_count: 1, active_credential_count: 1,
  scan_endpoint: 'http://masp.local/api/v1/scans',
  status_endpoint: 'http://masp.local/api/v1/scans/{scan_id}',
  deferred_endpoint: 'http://masp.local/api/v1/deferred-scans',
  authorization_header: 'Authorization: Bearer <api token>',
  icap_client_key_setting: 'MASP_ICAP_SERVICE_CLIENT_KEY=drive-gateway',
  generated_at: '2026-09-22T10:00:00Z',
}

function mount(payload: object = READY, status = 200, path = '/service-clients/3/setup') {
  const fetcher = vi.fn(async () => new Response(JSON.stringify(payload), { status }))
  vi.stubGlobal('fetch', fetcher)
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter initialEntries={[path]}>
    <Routes><Route path="/service-clients/:clientId/setup" element={<ClientSetup />} /></Routes>
  </MemoryRouter></QueryClientProvider>)
  return fetcher
}

describe('Connect a client', () => {
  it('shows the endpoints the other system needs and never a stored token', async () => {
    const fetcher = mount()
    await screen.findByText(/Drive Gateway/)
    expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/service-clients/3/readiness', expect.anything())
    expect(screen.getByText('POST http://masp.local/api/v1/scans')).toBeInTheDocument()
    expect(screen.getByText('MASP_ICAP_SERVICE_CLIENT_KEY=drive-gateway')).toBeInTheDocument()
    expect(screen.getByText('Authorization: Bearer <api token>')).toBeInTheDocument()
    expect(screen.getByText(/Ready through REST API\. This does not prove the other system can reach MASP/)).toBeInTheDocument()
    expect(screen.getByRole('listitem', { name: 'REST API connection' })).toHaveTextContent('Configured')
    expect(screen.getByRole('listitem', { name: 'ICAP gateway connection' })).toHaveTextContent('Not used')
  })

  it('explains why an assigned engine cannot run automation work', async () => {
    mount()
    await screen.findByText('VirusTotal')
    expect(screen.getByText(/Paid reputation service/)).toBeInTheDocument()
    expect(screen.getByText(/Eligibility is configuration, not health/)).toBeInTheDocument()
  })

  it('raises an alert and counts what is still blocking when not ready', async () => {
    const blocked = {
      ...READY, ready: false,
      checks: READY.checks.map((check, index) =>
        index > 1 ? { ...check, passed: false, detail: 'Needs attention.' } : check),
    }
    mount(blocked)
    await screen.findByRole('alert')
    expect(screen.getByRole('alert')).toHaveTextContent('Not ready: 2 routing item(s)')
    expect(screen.getAllByText('Needs attention.')).toHaveLength(2)
  })

  it('accepts a manifest-only client and points a missing grant at the Storage tab', async () => {
    const manifestOnly = {
      ...READY, ready: false, active_credential_count: 0,
      methods: [
        { ...READY.methods[0], in_use: false, ready: false, summary: 'Not set up: no active credential.',
          checks: [{ key: 'active_credential', label: 'Active API credential', passed: false, detail: 'Create a credential on the Credentials tab.' }] },
        READY.methods[1],
        { key: 'manifest', label: 'Manifest intake', in_use: true, ready: false, summary: 'Set up but not working.', checks: [
          { key: 'manifest_worker', label: 'The manifest worker runs for this client', passed: true, detail: 'It reports this client.' },
          { key: 'manifest_running', label: 'The worker is reading manifests', passed: true, detail: 'Last cycle 20 s ago.' },
          { key: 'manifest_grant', label: 'The client may read the watched share', passed: false,
            detail: 'Backend drive, prefix uploads. Grant it on the Storage tab, or every manifest is rejected.' }] },
      ],
    }
    mount(manifestOnly)
    await screen.findByRole('alert')
    expect(screen.getByRole('alert')).toHaveTextContent('Routing is complete, but no connection method is set up yet.')
    const manifest = screen.getByRole('listitem', { name: 'Manifest intake connection' })
    expect(manifest).toHaveTextContent('Needs attention')
    expect(manifest).toHaveTextContent('Grant storage access')
  })

  it('surfaces a read failure instead of implying the client is configured', async () => {
    const fetcher = mount({ detail: 'Service client not found.' }, 404)
    await screen.findByRole('alert')
    expect(screen.getByRole('alert')).toHaveTextContent('Service client not found.')
    expect(screen.queryByText(/Point the other system here/)).toBeNull()
    expect(fetcher).toHaveBeenCalledTimes(1)
  })

  it('rejects a non-numeric client ID before any request', () => {
    const fetcher = vi.fn()
    vi.stubGlobal('fetch', fetcher)
    render(<QueryClientProvider client={new QueryClient()}><MemoryRouter initialEntries={['/service-clients/abc/setup']}>
      <Routes><Route path="/service-clients/:clientId/setup" element={<ClientSetup />} /></Routes>
    </MemoryRouter></QueryClientProvider>)
    expect(screen.getByText('Invalid client ID')).toBeInTheDocument()
    expect(fetcher).not.toHaveBeenCalled()
  })
})
