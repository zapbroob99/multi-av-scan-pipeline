import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import { AreaNavigation, WorkspaceNavigation } from './workspace-navigation'
import { navigationFor } from '../lib/navigation'

describe('task navigation', () => {
  it('keeps storage available before a worker or folder exists without discovery requests', () => {
    const fetcher = vi.fn()
    vi.stubGlobal('fetch', fetcher)
    render(<MemoryRouter initialEntries={['/storage/access/42']}><WorkspaceNavigation admin /><AreaNavigation admin /></MemoryRouter>)
    const rail = screen.getByRole('navigation', { name: 'Workspace' })
    expect(within(rail).getByRole('link', { name: 'Storage' })).toHaveAttribute('aria-current', 'true')
    const sections = screen.getByRole('navigation', { name: 'Storage sections' })
    expect(within(sections).getByRole('link', { name: 'Sources & access' })).toHaveAttribute('aria-current', 'page')
    expect(within(sections).getByRole('link', { name: 'File intake' })).toHaveAttribute('href', '/storage/intake')
    expect(rail.querySelectorAll('[aria-current]')).toHaveLength(1)
    expect(sections.querySelectorAll('[aria-current]')).toHaveLength(1)
    expect(fetcher).not.toHaveBeenCalled()
  })
  it('shows analyst results without administrative editors', () => {
    render(<MemoryRouter initialEntries={['/storage/findings']}><WorkspaceNavigation admin={false} /><AreaNavigation admin={false} /></MemoryRouter>)
    for (const label of ['Integrations', 'Policies', 'Scan infrastructure', 'Administration', 'Sources & access', 'File intake']) {
      expect(screen.queryByRole('link', { name: label })).toBeNull()
    }
    expect(screen.getByRole('link', { name: 'Folder findings' })).toHaveAttribute('aria-current', 'page')
  })
  it('closes mobile navigation with Escape and restores toggle focus', async () => {
    render(<MemoryRouter><WorkspaceNavigation admin /></MemoryRouter>)
    const toggle = screen.getByRole('button', { name: 'Menu' })
    await userEvent.click(toggle)
    screen.getByRole('link', { name: 'Storage' }).focus()
    await userEvent.keyboard('{Escape}')
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(toggle).toHaveFocus()
  })
  it('resolves detail pages by their task and respects path boundaries', () => {
    expect(navigationFor('/scans/new')?.item.label).toBe('Submit sample')
    expect(navigationFor('/scans/42/results/7')?.item.label).toBe('Manual scans')
    expect(navigationFor('/api-ledger/scans/42')?.item.label).toBe('Integration scans')
    expect(navigationFor('/engines/hash-list')?.area.id).toBe('policies')
    expect(navigationFor('/system/retention')?.area.id).toBe('administration')
    expect(navigationFor('/systematic')).toBeNull()
  })
})
