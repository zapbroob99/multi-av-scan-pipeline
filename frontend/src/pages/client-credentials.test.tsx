import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import ClientCredentials from './client-credentials'

const token = 'synthetic-test-token-xxxxxxxxxxxxxxxxxxxxxxxx'
function mount(create = false, fail = false) {
  const client = new QueryClient()
  const fetcher = vi.fn(async (_url: string, options?: RequestInit) => options?.method === 'POST'
    ? fail ? new Response('{}', { status: 503 }) : new Response(JSON.stringify({ client_id: 2, credential_id: 3 }), { status: 201 })
    : new Response(JSON.stringify(create ? { engines: [{ id: 7, display_name: 'Engine', enabled: true }], incomplete: false } :
      { items: [{ id: 3, label: 'Existing', created_at: '2026-09-17', revoked_at: null, last_used_at: null }], next_after: null })))
  vi.stubGlobal('fetch', fetcher)
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/clients/2']}><Routes><Route path="/clients/:clientId" element={
    <ClientCredentials create={create} session={{ user: { id: 1, username: 'admin', role: 'admin' }, csrf_token: 'csrf' }} />
  } /></Routes></MemoryRouter></QueryClientProvider>)
  return { client, fetcher }
}

describe('Client credential workflows', () => {
  it('confirms creation without retaining the secret in query or mutation caches', async () => {
    const { client, fetcher } = mount(true)
    await screen.findByLabelText(/Engine/)
    await userEvent.type(screen.getByLabelText('Client key'), 'new-client')
    await userEvent.type(screen.getByLabelText('Display name'), 'New client')
    await userEvent.type(screen.getByLabelText('Default profile name'), 'Default')
    await userEvent.click(screen.getByLabelText(/Engine/))
    await userEvent.type(screen.getByLabelText('Credential label'), 'Initial')
    await userEvent.type(screen.getByLabelText('API token'), token)
    await userEvent.click(screen.getByRole('button', { name: 'Review client creation' }))
    expect(screen.getByRole('dialog')).not.toHaveTextContent(token)
    expect(fetcher.mock.calls.filter(([, o]) => o?.method === 'POST')).toHaveLength(0)
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Confirm' }))
    await screen.findByText('Client #2 created with credential #3.')
    expect(screen.getByLabelText('API token')).toHaveValue('')
    expect(client.getMutationCache().getAll()).toHaveLength(0)
    expect(JSON.stringify(client.getQueryData(['client-create-options']))).not.toContain(token)
    const write = fetcher.mock.calls.find(([, o]) => o?.method === 'POST')!
    expect(JSON.parse(String(write[1]?.body))).toMatchObject({ api_token: token, engine_ids: [7] })
    expect(write[1]?.headers).toMatchObject({ 'X-CSRF-Token': 'csrf' })
  })
  it('clears secret on cancellation and uncertain failure, without replay', async () => {
    const { fetcher } = mount(false, true)
    await screen.findByText('Existing')
    await userEvent.type(screen.getByLabelText('Credential label'), 'Second')
    await userEvent.type(screen.getByLabelText('API token'), token)
    await userEvent.click(screen.getByRole('button', { name: 'Review credential' }))
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.getByLabelText('API token')).toHaveValue('')
    await userEvent.type(screen.getByLabelText('API token'), token)
    await userEvent.click(screen.getByRole('button', { name: 'Review credential' }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('No automatic retry')
    expect(screen.getByLabelText('API token')).toHaveValue('')
    expect(screen.getByRole('button', { name: 'Review credential' })).toBeDisabled()
    expect(fetcher.mock.calls.filter(([, o]) => o?.method === 'POST')).toHaveLength(1)
  })
  it('scopes revocation to the client and selected credential', async () => {
    const { fetcher } = mount()
    await userEvent.click(await screen.findByRole('button', { name: 'Revoke credential #3' }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    await screen.findByText('Credential revoked. Refresh credentials to review its status.')
    expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/service-clients/2/credentials/3/revoke', expect.objectContaining({ method: 'POST', body: undefined }))
  })
})
