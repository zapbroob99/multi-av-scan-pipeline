import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import { EngineUsageDisclosure } from './engine-usage'

describe('Engine usage', () => {
  it('loads only on expansion, links to the selected profile and paginates without hiding disabled references', async () => {
    const fetcher = vi.fn(async (url: string) => new Response(JSON.stringify({ engine_id: 3, engine_name: 'Scanner', observed_at: 1700000000,
      profiles: url.includes('after=20') ? [] : [{ profile_id: 20, profile_name: 'Named', profile_enabled: false, is_default: false,
        client_id: 4, client_name: 'Client', client_enabled: false, names_truncated: false }], next_after: url.includes('after=20') ? null : 20 })))
    vi.stubGlobal('fetch', fetcher)
    render(<QueryClientProvider client={new QueryClient()}><MemoryRouter><EngineUsageDisclosure instanceId={3} /></MemoryRouter></QueryClientProvider>)
    expect(fetcher).not.toHaveBeenCalled()
    await userEvent.click(screen.getByText('Profiles using this engine'))
    expect(await screen.findByRole('link', { name: 'Client / Named' })).toHaveAttribute('href', '/service-clients/4/overview?profile_id=20')
    expect(screen.getByText(/client disabled/)).toHaveTextContent('profile disabled')
    await userEvent.click(screen.getByRole('button', { name: 'Next references' }))
    await screen.findByText(/No current profile references on this page/)
    expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/engines/3/usage?after=20', expect.anything())
    expect(screen.queryByRole('link', { name: 'Client / Named' })).toBeNull()
  })
})
