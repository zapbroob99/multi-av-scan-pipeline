import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import HashList, { parseHashes } from './hash-list'
import type { Session } from '../lib/api'

const A = 'a'.repeat(64), B = 'b'.repeat(64)
const SESSION = { csrf_token: 'csrf', user: { id: 1, username: 'admin', role: 'admin' } } as unknown as Session
const ENTRY = { id: 7, sha256: A, list_kind: 'block', note: '<b>Incident 14</b>', created_by: 'admin', created_at: 1790000000 }

function mount({ engines = [{ id: 1, adapter_key: 'hash_list', enabled: true }], added = { added: 1, existing: [{ sha256: B, list_kind: 'block' }] } } = {}) {
  const fetcher = vi.fn(async (url: string, init?: RequestInit) => {
    if (url.startsWith('/api/ui/v1/engines')) return new Response(JSON.stringify({ adapters: [], engines, pools: [] }))
    if (init?.method === 'POST') return new Response(JSON.stringify(added), { status: 201 })
    if (init?.method === 'DELETE') return new Response(null, { status: 204 })
    return new Response(JSON.stringify({ items: [ENTRY], next_before: 7, counts: { block: 1, allow: 0 } }))
  })
  vi.stubGlobal('fetch', fetcher)
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter><HashList session={SESSION} /></MemoryRouter></QueryClientProvider>)
  return fetcher
}

function bodyOf(fetcher: ReturnType<typeof mount>, method: string) {
  const call = fetcher.mock.calls.find(([, init]) => init?.method === method)
  return call ? JSON.parse(String(call[1]!.body)) : undefined
}

describe('parseHashes', () => {
  it('splits, lowercases and dedupes, reporting malformed values', () => {
    expect(parseHashes(`${A.toUpperCase()}\n${A}, ${B};nope`)).toEqual({ hashes: [A, B], invalid: ['nope'] })
  })
})

describe('Hash list', () => {
  it('renders entries as inert text with first-page counts and a keyset cursor', async () => {
    const fetcher = mount()
    await screen.findByText(A)
    expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/hash-list?limit=20', expect.anything())
    expect(screen.getByText('<b>Incident 14</b>')).toBeInTheDocument()
    expect(document.querySelector('td b')).toBeNull()
    expect(screen.getByText(/1 blocked · 0 allowed/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Older entries' }))
    await waitFor(() => expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/hash-list?before=7&limit=20', expect.anything()))
  })

  it('requires an explicit list and a confirmation before adding', async () => {
    const fetcher = mount()
    await screen.findByText(A)
    await userEvent.type(screen.getByLabelText(/SHA-256 values/), `${B}\n${B}`)
    await userEvent.click(screen.getByRole('button', { name: 'Review addition' }))
    expect(bodyOf(fetcher, 'POST')).toBeUndefined()
    await userEvent.selectOptions(screen.getByLabelText('Target list'), 'allow')
    await userEvent.type(screen.getByLabelText(/Note/), 'Signed installer')
    await userEvent.click(screen.getByRole('button', { name: 'Review addition' }))
    const dialog = await screen.findByRole('dialog')
    expect(dialog).toHaveTextContent('does not clear or allow these files')
    expect(bodyOf(fetcher, 'POST')).toBeUndefined()
    await userEvent.click(within(dialog).getByRole('button', { name: 'Confirm addition' }))
    await waitFor(() => expect(bodyOf(fetcher, 'POST')).toEqual({ list_kind: 'allow', hashes: [B], note: 'Signed installer' }))
    const status = await screen.findByText(/already listed and left unchanged/)
    expect(status.closest('[role=status]')).toHaveTextContent('on the blocklist')
  })

  it('refuses malformed input without sending it', async () => {
    const fetcher = mount()
    await screen.findByText(A)
    await userEvent.selectOptions(screen.getByLabelText('Target list'), 'block')
    await userEvent.type(screen.getByLabelText(/SHA-256 values/), `${A}\nnot-a-hash`)
    await userEvent.click(screen.getByRole('button', { name: 'Review addition' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Not a SHA-256 value: not-a-hash')
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(bodyOf(fetcher, 'POST')).toBeUndefined()
  })

  it('removes an entry only after confirmation', async () => {
    const fetcher = mount()
    await screen.findByText(A)
    await userEvent.click(screen.getByRole('button', { name: `Remove ${A}` }))
    const dialog = await screen.findByRole('dialog')
    expect(fetcher.mock.calls.some(([, init]) => init?.method === 'DELETE')).toBe(false)
    await userEvent.click(within(dialog).getByRole('button', { name: 'Confirm removal' }))
    await waitFor(() => expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/hash-list/7', expect.objectContaining({ method: 'DELETE' })))
    expect(await screen.findByText(`Removed ${A} from the blocklist.`)).toBeInTheDocument()
  })

  it('warns when no enabled Hash List engine will check the entries', async () => {
    mount({ engines: [{ id: 1, adapter_key: 'hash_list', enabled: false }] })
    expect(await screen.findByText(/No enabled Hash List engine exists/)).toBeInTheDocument()
  })
})
