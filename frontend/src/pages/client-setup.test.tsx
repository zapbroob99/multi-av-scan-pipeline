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
    { key: 'active_credential', label: 'Active API credential', passed: true, detail: '1 active credential(s).' },
  ],
  profile_id: 9, profile_name: 'Default routing',
  engines: [
    { id: 1, display_name: 'Metadata', adapter_key: 'static_metadata', enabled: true, eligible: true, excluded_reason: null },
    { id: 2, display_name: 'VirusTotal', adapter_key: 'virustotal', enabled: true, eligible: false,
      excluded_reason: 'Metered reputation adapter; API and ICAP exclude it before job creation.' },
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
    expect(screen.getByText(/does not prove the integration can reach MASP/)).toBeInTheDocument()
  })

  it('explains why an assigned engine cannot run automation work', async () => {
    mount()
    await screen.findByText('VirusTotal')
    expect(screen.getByText(/Metered reputation adapter/)).toBeInTheDocument()
    expect(screen.getByText(/Eligibility is configuration, not health/)).toBeInTheDocument()
  })

  it('raises an alert and counts what is still blocking when not ready', async () => {
    const blocked = {
      ...READY, ready: false,
      checks: READY.checks.map((check, index) =>
        index > 2 ? { ...check, passed: false, detail: 'Needs attention.' } : check),
    }
    mount(blocked)
    await screen.findByRole('alert')
    expect(screen.getByRole('alert')).toHaveTextContent('Not ready: 2 item(s)')
    expect(screen.getAllByText('Needs attention.')).toHaveLength(2)
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
