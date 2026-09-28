import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi } from 'vitest'
import { SupportBundleButton } from './support-bundle'

const SESSION = { user: { id: 1, username: 'admin', role: 'admin' }, csrf_token: 'csrf' }

describe('Support bundle', () => {
  it('explains what is left out, then downloads the file with one audited POST', async () => {
    const fetcher = vi.fn(async () => new Response(JSON.stringify({
      filename: 'masp-support-20260928T070000Z.json', media_type: 'application/json', content: '{"schema_version": 1}' })))
    vi.stubGlobal('fetch', fetcher)
    const create = vi.fn(() => 'blob:bundle')
    vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: create, revokeObjectURL: vi.fn() }))
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    render(<QueryClientProvider client={new QueryClient()}><SupportBundleButton session={SESSION} /></QueryClientProvider>)
    await userEvent.click(screen.getByRole('button', { name: 'Support bundle' }))
    expect(screen.getByRole('dialog')).toHaveTextContent('passwords, tokens and keys')
    expect(screen.getByRole('dialog')).toHaveTextContent('recorded in the audit trail')
    expect(fetcher).not.toHaveBeenCalled()
    await userEvent.click(screen.getByRole('button', { name: 'Download' }))
    await vi.waitFor(() => expect(click).toHaveBeenCalledTimes(1))
    const [url, options] = fetcher.mock.calls[0] as unknown as [string, RequestInit]
    expect(options.method).toBe('POST')
    expect(url).toBe('/api/ui/v1/system/support-bundle')
    expect(options.headers).toMatchObject({ 'X-CSRF-Token': 'csrf' })
    expect(create).toHaveBeenCalledTimes(1)
    click.mockRestore()
  })
})
