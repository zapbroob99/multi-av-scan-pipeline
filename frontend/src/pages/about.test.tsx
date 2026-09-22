import { render, screen } from '@testing-library/react'
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
  it('shows capability state and marks the truncated engine list', async () => {
    const fetcher = mount('admin')
    await screen.findByText('MASP 0.1.0')
    expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/about', expect.anything())
    expect(screen.getByText(/7: ClamAV, Defender, YARA, Metadata, VirusTotal and more/)).toBeInTheDocument()
    expect(screen.getByText('Enabled')).toBeInTheDocument()
    expect(screen.getByText('Not configured')).toBeInTheDocument()
    expect(screen.getByText('3 registered · 2 accepting work')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Service clients' })).toHaveAttribute('href', '/service-clients')
  })

  it('omits admin-only counts and links for an analyst', async () => {
    mount('analyst', { ...PAYLOAD, service_client_count: null })
    await screen.findByText('MASP 0.1.0')
    expect(screen.queryByText('Service clients')).toBeNull()
    expect(screen.getByRole('link', { name: 'Hash scan' })).toHaveAttribute('href', '/hash-scan')
  })

  it('keeps the product description usable when the runtime read fails', async () => {
    const fetcher = vi.fn(async () => new Response(JSON.stringify({ detail: 'Unavailable' }), { status: 503 }))
    vi.stubGlobal('fetch', fetcher)
    render(<QueryClientProvider client={new QueryClient()}><MemoryRouter><About session={session('admin')} /></MemoryRouter></QueryClientProvider>)
    await screen.findByRole('alert')
    expect(screen.getByText('What MASP is not')).toBeInTheDocument()
    expect(screen.queryByText(/MASP 0\.1\.0/)).toBeNull()
    expect(fetcher).toHaveBeenCalledTimes(1)
  })
})
