import { describe, expect, it, vi } from 'vitest'
import { request, ApiError } from './api'

describe('Generated-contract transport', () => {
  it('encodes path/query values and preserves private GET and abort behavior', async () => {
    const fetcher = vi.fn(async (_url: string, _options: RequestInit) => new Response('{"name":"ok.yar"}'))
    vi.stubGlobal('fetch', fetcher)
    const signal = new AbortController().signal
    await request('/api/ui/v1/engines/{instance_id}/rules/{name}/toggle', 'post', {
      params: { instance_id: 3, name: 'file name%?.yar' }, csrf: 'token', signal,
    })
    expect(fetcher.mock.calls[0]).toEqual(['/api/ui/v1/engines/3/rules/file%20name%25%3F.yar/toggle', expect.objectContaining({
      method: 'POST', credentials: 'same-origin', cache: 'no-store', signal,
      headers: expect.objectContaining({ 'X-CSRF-Token': 'token', 'X-MASP-UI': '1' }),
    })])
    await request('/api/ui/v1/dashboard/scans', 'get', { query: new URLSearchParams({ q: '%_!' }) })
    expect(fetcher.mock.calls[1][0]).toBe('/api/ui/v1/dashboard/scans?q=%25_%21')
  })
  it('serializes JSON but leaves multipart boundaries to the browser', async () => {
    const fetcher = vi.fn(async (_url: string, _options: RequestInit) => new Response('{}'))
    vi.stubGlobal('fetch', fetcher)
    await request('/api/ui/v1/session/login', 'post', { body: { username: 'a', password: 'b' } })
    expect(fetcher.mock.calls[0][1]).toMatchObject({ body: '{"username":"a","password":"b"}', headers: { 'Content-Type': 'application/json' } })
    const body = new FormData()
    body.set('sample', new File(['benign'], 'sample.txt'))
    await request('/api/ui/v1/scans', 'post', { body, csrf: 'token' })
    expect(fetcher.mock.calls[1][1].body).toBe(body)
    expect(fetcher.mock.calls[1][1].headers).not.toHaveProperty('Content-Type')
  })
  it('handles 204, server errors and session expiry without retries', async () => {
    const expired = vi.fn()
    window.addEventListener('masp-session-expired', expired)
    try {
      const fetcher = vi.fn(async () => new Response(null, { status: 204 }))
      vi.stubGlobal('fetch', fetcher)
      expect(await request('/api/ui/v1/session/logout', 'post', { csrf: 'token' })).toBeUndefined()
      fetcher.mockImplementation(async () => new Response('{"detail":"Expired"}', { status: 401 }))
      await expect(request('/api/ui/v1/dashboard/scans', 'get', {})).rejects.toMatchObject({ status: 401, message: 'Expired' })
      expect(expired).toHaveBeenCalledTimes(1)
      await expect(request('/api/ui/v1/session', 'get', {})).rejects.toBeInstanceOf(ApiError)
      expect(expired).toHaveBeenCalledTimes(1)
      fetcher.mockImplementation(async () => new Response('proxy failed', { status: 502 }))
      await expect(request('/api/ui/v1/session', 'get', {})).rejects.toMatchObject({ status: 502, message: 'Request failed (502).' })
      expect(fetcher).toHaveBeenCalledTimes(4)
    } finally { window.removeEventListener('masp-session-expired', expired) }
  })
})
