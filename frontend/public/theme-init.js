try {
  const stored = localStorage.getItem('masp-console-theme')
  document.documentElement.dataset.theme = stored === 'light' || stored === 'dark'
    ? stored
    : matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
} catch {
  document.documentElement.dataset.theme = 'dark'
}
