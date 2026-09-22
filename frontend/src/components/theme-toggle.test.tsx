import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ThemeToggle, THEME_STORAGE_KEY } from './theme-toggle'

describe('Theme toggle', () => {
  beforeEach(() => {
    document.documentElement.dataset.theme = ''
    document.documentElement.style.colorScheme = ''
    localStorage.clear()
    let meta = document.querySelector('meta[name="theme-color"]')
    if (!meta) { meta = document.createElement('meta'); meta.setAttribute('name', 'theme-color'); document.head.append(meta) }
  })

  it('uses the system preference initially, then persists an explicit choice', async () => {
    vi.stubGlobal('matchMedia', vi.fn(() => ({ matches: true })))
    render(<ThemeToggle />)
    expect(document.documentElement.dataset.theme).toBe('light')
    await userEvent.click(screen.getByRole('button', { name: 'Switch to dark theme' }))
    expect(document.documentElement.dataset.theme).toBe('dark')
    expect(document.documentElement.style.colorScheme).toBe('dark')
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('dark')
    expect(document.querySelector('meta[name="theme-color"]')).toHaveAttribute('content', '#101820')
  })

  it('honors a theme applied before React starts to prevent a color flash', () => {
    document.documentElement.dataset.theme = 'light'
    localStorage.setItem(THEME_STORAGE_KEY, 'dark')
    render(<ThemeToggle />)
    expect(document.documentElement.dataset.theme).toBe('light')
    expect(screen.getByRole('button', { name: 'Switch to dark theme' })).toBeInTheDocument()
  })

  it('still changes the current page when storage is unavailable', async () => {
    document.documentElement.dataset.theme = 'dark'
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new DOMException('blocked') })
    render(<ThemeToggle />)
    await userEvent.click(screen.getByRole('button', { name: 'Switch to light theme' }))
    expect(document.documentElement.dataset.theme).toBe('light')
  })
})
