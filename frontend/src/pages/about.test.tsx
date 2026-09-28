import { render, screen, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import About from './about'
import type { Session } from '../lib/api'

const PAYLOAD = {
  app_version: '0.1.0', queue_mode: 'Durable engine job queue', worker_transport: 'Database or HTTPS control API',
  directory_login_enabled: true, secret_encryption_available: false, enabled_engine_count: 7,
  enabled_engine_names: ['ClamAV', 'Defender', 'YARA', 'Metadata', 'VirusTotal'], engine_names_truncated: true,
  hash_engine_count: 1, registered_nodes: 3, schedulable_nodes: 2, service_client_count: 4,
  release: 'masp-pilot:0.1.0-pilot.7', python_version: '3.12.7', database: 'PostgreSQL 16.4',
  engines: [
    { name: 'Gateway ClamAV', kind: 'ClamAV', product_version: 'ClamAV 1.4.2', engine_version: '1.4.2', signature_version: '27771',
      last_checked_at: '2026-09-20T09:58:00+00:00' },
    { name: 'Rules', kind: 'YARA', product_version: null, engine_version: null, signature_version: null, last_checked_at: null },
  ],
  engines_truncated: false, worker_agent_versions: ['0.1.0', '0.1.1'],
  generated_at: '2026-09-20T10:00:00Z',
}

function session(role: 'admin' | 'analyst') {
  return { user: { id: 1, username: 'operator', role, auth_source: 'local' }, csrf_token: 'token' } as unknown as Session
}

function mount(role: 'admin' | 'analyst', payload: object = PAYLOAD) {
  const fetcher = vi.fn(async () => new Response(JSON.stringify(payload)))
  vi.stubGlobal('fetch', fetcher)
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter><About session={session(role)} /></MemoryRouter></QueryClientProvider>)
  return fetcher
}

describe('About', () => {
  it('lists build, engine and worker versions as plain rows', async () => {
    const fetcher = mount('admin')
    await screen.findByText('MASP 0.1.0')
    expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/about', expect.anything())
    expect(screen.getByText('masp-pilot:0.1.0-pilot.7')).toBeInTheDocument()
    expect(screen.getByText('3.12.7')).toBeInTheDocument()
    expect(screen.getByText('PostgreSQL 16.4')).toBeInTheDocument()
    const clamav = screen.getByRole('row', { name: /Gateway ClamAV/ })
    expect(within(clamav).getByText('ClamAV 1.4.2')).toBeInTheDocument()
    expect(within(clamav).getByText('27771')).toBeInTheDocument()
    expect(within(screen.getByRole('row', { name: /Rules/ })).getAllByText('—')).toHaveLength(3)
    expect(within(screen.getByRole('row', { name: /Rules/ })).getByText('Not recorded')).toBeInTheDocument()
    expect(screen.getByText('0.1.0, 0.1.1')).toBeInTheDocument()
    expect(screen.getByText('3 registered · 2 accepting work')).toBeInTheDocument()
    expect(screen.getByText('Enabled')).toBeInTheDocument()
    expect(screen.getByText('Not configured')).toBeInTheDocument()
    expect(screen.getByText('Service clients')).toBeInTheDocument()
    expect(screen.queryByText('What MASP is not')).toBeNull()
  })

  it('omits admin-only counts for an analyst', async () => {
    mount('analyst', { ...PAYLOAD, service_client_count: null })
    await screen.findByText('MASP 0.1.0')
    expect(screen.queryByText('Service clients')).toBeNull()
  })

  it('says when the engine list is cut and when no release is recorded', async () => {
    mount('admin', { ...PAYLOAD, release: null, engines_truncated: true, enabled_engine_count: 25 })
    await screen.findByText('MASP 0.1.0')
    expect(screen.getByText(/25 enabled; the first 2 are listed/)).toBeInTheDocument()
    expect(within(screen.getByText('Release image').parentElement!).getByText('—')).toBeInTheDocument()
  })

  it('shows the error without inventing values when the runtime read fails', async () => {
    const fetcher = vi.fn(async () => new Response(JSON.stringify({ detail: 'Unavailable' }), { status: 503 }))
    vi.stubGlobal('fetch', fetcher)
    render(<QueryClientProvider client={new QueryClient()}><MemoryRouter><About session={session('admin')} /></MemoryRouter></QueryClientProvider>)
    await screen.findByRole('alert')
    expect(screen.getByRole('heading', { name: 'About MASP' })).toBeInTheDocument()
    expect(screen.queryByText(/MASP 0\.1\.0/)).toBeNull()
    expect(fetcher).toHaveBeenCalledTimes(1)
  })
})
