import { test, expect } from '@playwright/test'

// acceptance-24.bin in the console fixture: a failed manual scan carried into file history.
const FILE = (24).toString(16).padStart(64, '0')

test('analyst reads MASP history before asking any provider', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await page.goto(`hash-scan?sha256=${FILE}`)
  await page.getByLabel('Username', { exact: true }).fill('console-analyst')
  await page.getByLabel('Password', { exact: true }).fill('console-test-only')
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  const local = page.getByRole('region', { name: 'Seen in MASP' })
  await expect(local).toContainText('Scanned 1 time')
  await expect(page.getByRole('button', { name: 'Ask external engines (uses quota)' })).toBeDisabled()

  await local.getByRole('link', { name: 'Open file history' }).click()
  await expect(page.getByRole('heading', { name: 'File history' })).toBeVisible()
  await expect(page.getByRole('region', { name: 'Latest engine results' })).toContainText('Static Metadata')
  await expect(page.getByText('Not listed')).toBeVisible()
  await page.getByRole('link', { name: 'acceptance-24.bin' }).click()
  await expect(page).toHaveURL(/\/console\/scans\/\d+$/)
  await page.getByRole('link', { name: 'File history' }).click()
  await expect(page).toHaveURL(new RegExp(`/console/files/${FILE}$`))

  await page.setViewportSize({ width: 390, height: 844 })
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
  await page.screenshot({ path: '../artifacts/console-e2e/file-history-mobile.png', fullPage: true })
  expect(errors).toEqual([])
})
