import { useState } from 'react'
import { Moon, Sun } from 'lucide-react'
import { Button } from './ui/button'

export type Theme = 'light' | 'dark'
export const THEME_STORAGE_KEY = 'masp-console-theme'

function initialTheme(): Theme {
  const applied = document.documentElement.dataset.theme
  if (applied === 'light' || applied === 'dark') return applied
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY)
    if (stored === 'light' || stored === 'dark') return stored
  } catch { /* Storage can be disabled by browser policy. */ }
  return window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
}

function applyTheme(theme: Theme) {
  document.documentElement.dataset.theme = theme
  document.documentElement.style.colorScheme = theme
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', theme === 'light' ? '#f5f7fb' : '#101820')
}

export function ThemeToggle({ className }: { className?: string }) {
  const [theme, setTheme] = useState<Theme>(() => {
    const value = initialTheme()
    applyTheme(value)
    return value
  })
  const next = theme === 'dark' ? 'light' : 'dark'
  return <Button type="button" variant="secondary" className={className} aria-label={`Switch to ${next} theme`}
    title={`Switch to ${next} theme`} onClick={() => {
      applyTheme(next)
      try { localStorage.setItem(THEME_STORAGE_KEY, next) } catch { /* Theme still applies for this page. */ }
      setTheme(next)
    }}>
    {theme === 'dark' ? <Sun size={17} aria-hidden="true" /> : <Moon size={17} aria-hidden="true" />}
  </Button>
}
