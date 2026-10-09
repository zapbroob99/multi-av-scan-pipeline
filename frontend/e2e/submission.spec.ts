import { test, expect } from '@playwright/test'

test('analyst sends a benign file and sees accepted scan in manual history', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await page.goto('scans/new')
  await page.getByLabel('Username').fill('console-analyst')
  await page.getByLabel('Password').fill('console-test-only')
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Submit sample', exact: true })).toBeVisible()
  await page.getByLabel('Sample file').setInputFiles({ name: 'browser-benign.txt', mimeType: 'text/plain', buffer: Buffer.from('Benign browser acceptance fixture. No executable content.') })
  await page.getByLabel('Case name').fill('IR-browser-upload')
  await page.getByLabel('Priority').selectOption('High')
  await page.getByLabel('Analyst note').fill('Synthetic data in a disposable database.')
  await page.screenshot({ path: '../artifacts/console-e2e/submission-desktop.png', fullPage: true })
  await page.setViewportSize({ width: 390, height: 844 })
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
  await page.screenshot({ path: '../artifacts/console-e2e/submission-mobile.png', fullPage: true })
  const submitted = page.waitForResponse(response => response.url().endsWith('/api/ui/v1/scans') && response.request().method() === 'POST')
  await page.getByRole('button', { name: 'Create scan' }).click()
  expect((await submitted).status()).toBe(202)
  // Submitting now opens the report directly; the acceptance wording moves with it.
  await expect(page.getByText(/not a completed scan or a clean verdict/)).toBeVisible()
  await expect(page).toHaveURL(/\/console\/scans\/\d+\?accepted=1$/)
  // The submission page's own acceptance card shows the same words while the report
  // page is still loading; wait for the report itself, or its arrival closes the menu
  // opened below (navigation closes it on every page change).
  await expect(page.getByRole('button', { name: 'Refresh report' })).toBeVisible()
  const report = new URL(page.url()).pathname
  // Phone widths collapse the grouped navigation behind the Menu button.
  await page.getByRole('button', { name: 'Menu', exact: true }).click()
  await page.getByRole('navigation', { name: 'Workspace' }).getByRole('link', { name: 'Dashboard', exact: true }).click()
  await page.getByLabel('Search scans').fill('IR-browser-upload')
  await page.getByRole('button', { name: 'Apply filters' }).click()
  await expect(page.locator('tbody tr')).toHaveCount(1)
  await expect(page.getByRole('link', { name: 'browser-benign.txt' })).toHaveAttribute('href', report!)
  await expect(page.locator('tbody')).toContainText('queued')
  await expect(page.locator('tbody')).toContainText('Pending')
  expect(errors).toEqual([])
})
