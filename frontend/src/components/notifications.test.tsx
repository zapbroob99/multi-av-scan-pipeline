import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import { NotificationBell } from './notifications'

const FEED = {
  unread: 1, unread_capped: false, cleared: false,
  detections: [
    { scan_id: 41, source: 'icap', client_name: 'fil', filename: 'bundle.zip/<b>payload</b>.exe', archive_member: true,
      verdict: 'critical', risk_score: 90, completed_at: '2026-10-05T10:41:00+00:00', unread: true },
    { scan_id: 7, source: 'manual', client_name: null, filename: 'setup.exe', archive_member: false,
      verdict: 'high', risk_score: 70, completed_at: '2026-10-05T09:02:00+00:00', unread: false },
  ],
}
const READ_FEED = { ...FEED, unread: 0, detections: FEED.detections.map(item => ({ ...item, unread: false })) }
const HEALTH = {
  overall: 'critical', generated_at: '2026-10-05T10:45:00+00:00', waiting_reason: null,
  checks: [
    { key: 'signatures', label: 'ClamAV signatures', state: 'critical', summary: 'Signatures are 4 days old.', detail: null, link: '/engines' },
    { key: 'workers', label: 'Workers', state: 'ok', summary: '1 worker(s) accepting work.', detail: null, link: '/system' },
  ],
}

function mount({ admin = true, feed = FEED, health = HEALTH }: { admin?: boolean; feed?: object; health?: object | null } = {}) {
  const fetcher = vi.fn(async (url: string, options?: RequestInit) => {
    if (options?.method === 'POST') return new Response(null, { status: 204 })
    if (url.endsWith('/system/health')) return health ? new Response(JSON.stringify(health)) : new Response(JSON.stringify({ detail: 'down' }), { status: 503 })
    return new Response(JSON.stringify(feed))
  })
  vi.stubGlobal('fetch', fetcher)
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter><NotificationBell admin={admin} csrf="csrf" /></MemoryRouter></QueryClientProvider>)
  return fetcher
}

describe('Notification bell', () => {
  it('counts new detections and failing checks, and lists both for an administrator', async () => {
    mount()
    const toggle = await screen.findByRole('button', { name: 'Notifications, 2 need attention' })
    await userEvent.click(toggle)
    const panel = screen.getByRole('dialog', { name: 'Notifications' })
    const system = within(panel).getByRole('region', { name: 'System' })
    expect(system).toHaveTextContent('ClamAV signatures')
    expect(system).not.toHaveTextContent('Workers')
    expect(within(system).getByRole('link', { name: 'Open ClamAV signatures' })).toHaveAttribute('href', '/engines')
    const detections = within(panel).getByRole('region', { name: 'Detections' })
    const links = within(detections).getAllByRole('link')
    expect(links[0]).toHaveAttribute('href', '/api-ledger/scans/41')
    expect(links[0]).toHaveTextContent('bundle.zip/<b>payload</b>.exe')
    expect(links[0]).toHaveTextContent('Critical risk · ICAP · fil · archive member')
    expect(links[1]).toHaveAttribute('href', '/scans/7')
    expect(document.querySelector('b')).toBeNull()
    await userEvent.keyboard('{Escape}')
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(toggle).toHaveFocus()
  })

  it('marks read through the newest detection it showed', async () => {
    const fetcher = mount()
    await userEvent.click(await screen.findByRole('button', { name: /^Notifications/ }))
    await userEvent.click(screen.getByRole('button', { name: 'Mark as read' }))
    const write = fetcher.mock.calls.find(([, options]) => options?.method === 'POST')
    expect(write?.[0]).toBe('/api/ui/v1/notifications/read')
    expect(JSON.parse(String(write?.[1]?.body))).toEqual({ through_scan_id: 41 })
    expect(write?.[1]?.headers).toMatchObject({ 'X-CSRF-Token': 'csrf' })
  })

  it('clears the shown detections from the list and says where history is', async () => {
    const fetcher = mount({ admin: false })
    await userEvent.click(await screen.findByRole('button', { name: /^Notifications/ }))
    await userEvent.click(screen.getByRole('button', { name: 'Clear' }))
    const write = fetcher.mock.calls.find(([, options]) => options?.method === 'POST')
    expect(write?.[0]).toBe('/api/ui/v1/notifications/clear')
    expect(JSON.parse(String(write?.[1]?.body))).toEqual({ through_scan_id: 41 })
  })

  it('offers only Clear when every listed detection is read', async () => {
    mount({ admin: false, feed: READ_FEED })
    await userEvent.click(await screen.findByRole('button', { name: 'Notifications' }))
    expect(screen.queryByRole('button', { name: 'Mark as read' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Clear' })).toBeInTheDocument()
  })

  it('points to history once the list was cleared', async () => {
    mount({ admin: false, feed: { detections: [], unread: 0, unread_capped: false, cleared: true } })
    await userEvent.click(await screen.findByRole('button', { name: 'Notifications' }))
    expect(screen.getByText(/No new detections/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'API ledger' })).toHaveAttribute('href', '/api-ledger')
    expect(screen.queryByRole('button', { name: 'Clear' })).toBeNull()
  })

  it('never reads health for an analyst and says when it cannot read it for an administrator', async () => {
    const analyst = mount({ admin: false, feed: { ...FEED, unread: 0, detections: [] } })
    await userEvent.click(await screen.findByRole('button', { name: 'Notifications' }))
    expect(screen.getByText('No detections recorded.')).toBeInTheDocument()
    expect(screen.queryByRole('region', { name: 'System' })).toBeNull()
    expect(analyst.mock.calls.some(([url]) => String(url).endsWith('/system/health'))).toBe(false)
  })

  it('treats an unreadable health report as unknown, never as normal', async () => {
    mount({ health: null, feed: READ_FEED })
    await userEvent.click(await screen.findByRole('button', { name: 'Notifications, 1 need attention' }))
    expect(screen.getByText(/system state is unknown/)).toBeInTheDocument()
    expect(screen.queryByText('All systems normal.')).toBeNull()
  })

  it('shows an administrator that all systems are normal', async () => {
    mount({ health: { ...HEALTH, overall: 'ok', checks: [HEALTH.checks[1]] }, feed: READ_FEED })
    await userEvent.click(await screen.findByRole('button', { name: 'Notifications' }))
    expect(await screen.findByText('All systems normal.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Mark as read' })).toBeNull()
  })
})
