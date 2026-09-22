import { test, expect } from '@playwright/test'

test('analyst opens hash lookup without triggering a provider request', async ({ page }) => {
  await page.goto('hash-scan')
  await page.getByLabel('Username').fill('console-analyst')
  await page.getByLabel('Password').fill('console-test-only')
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Hash lookup' })).toBeVisible()
  await expect(page.getByText('No hash-capable engine is added and enabled in MASP.')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Look up hash' })).toBeDisabled()
  await page.setViewportSize({ width: 390, height: 844 })
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
  await page.screenshot({ path: '../artifacts/console-e2e/hash-scan-mobile.png', fullPage: true })
  await page.reload()
  await expect(page.getByRole('heading', { name: 'Hash lookup' })).toBeVisible()
})
