import type { ReactElement } from 'react'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import { HealthPanel } from './health-panel'

const REPORT = {
  overall: 'critical', generated_at: '2026-09-28T07:00:00+00:00',
  waiting_reason: 'No worker is online and accepting work, so queued scans cannot start.',
  checks: [
    { key: 'workers', label: 'Workers', state: 'critical', summary: 'No worker is accepting work.', detail: 'Every worker is offline.', link: '/system' },
    { key: 'storage', label: 'Sample storage', state: 'ok', summary: '40% used; 60.0 GiB free.', detail: null, link: '/system/retention' },
    { key: 'icap', label: 'ICAP gateway', state: 'inactive', summary: 'No ICAP gateway has reported.', detail: null, link: '/system/delivery' },
  ],
}

function mount(node: ReactElement, report: object = REPORT) {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(report))))
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter>{node}</MemoryRouter></QueryClientProvider>)
}

describe('Health', () => {
  it('lists failing checks with the next screen and explains the waiting queue', async () => {
    mount(<HealthPanel />)
    expect(await screen.findByText('Action required')).toBeInTheDocument()
    expect(screen.getByText(/Why scans are waiting:/).parentElement).toHaveTextContent('No worker is online')
    expect(screen.getByText('Every worker is offline.')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open Workers' })).toHaveAttribute('href', '/system')
    // Parts that are not in use are named once instead of listed as rows.
    expect(screen.queryByRole('link', { name: 'Open ICAP gateway' })).toBeNull()
    expect(screen.getByText('Not in use: ICAP gateway.')).toBeInTheDocument()
  })
})
