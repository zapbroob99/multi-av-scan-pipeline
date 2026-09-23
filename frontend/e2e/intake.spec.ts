import { test, expect } from '@playwright/test'

test('admin sees a stopped manifest worker, backlog, rejections and pre-scan failures without paths', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await page.goto('system/intake')
  await page.getByLabel('Username', { exact: true }).fill('console-admin')
  await page.getByLabel('Password', { exact: true }).fill('console-test-only')
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Deferred intake' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Deferred intake' })).toHaveAttribute('aria-current', 'page')

  const worker = page.getByRole('article', { name: 'Manifest worker' })
  await expect(worker.getByRole('alert').filter({ hasText: 'stopped or is stuck' })).toBeVisible()
  await expect(worker.getByRole('alert').filter({ hasText: "The last cycle failed: OSError: [Errno 5] I/O error: '<path>'" })).toBeVisible()
  await expect(worker.getByText('console-client')).toBeVisible()

  await expect(page.getByRole('article', { name: 'Deferred queue' })).toContainText('1 (1 retrying after an error)')
  const rejections = page.getByRole('region', { name: 'Rejected manifests table' })
  await expect(rejections).toContainText('incoming/2026/09/23/intake-fixture.json')
  await expect(rejections).toContainText("Permission denied: '<path>'")
  const failures = page.getByRole('region', { name: 'Failed submissions table' })
  await expect(failures).toContainText('intake-fixture-failed.pdf')
  await expect(failures).toContainText('Source SHA-256 does not match expected_sha256.')
  await expect(page.locator('main')).not.toContainText('/mnt/fixture-share')

  await page.setViewportSize({ width: 390, height: 844 })
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
  await page.setViewportSize({ width: 1280, height: 800 })

  await page.getByRole('button', { name: 'Sign out' }).click()
  await page.getByLabel('Username', { exact: true }).fill('console-analyst')
  await page.getByLabel('Password', { exact: true }).fill('console-test-only')
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Administrator access required' })).toBeVisible()
  expect(errors).toEqual([])
})
