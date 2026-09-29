import { test, expect } from '@playwright/test'

async function signIn(page: import('@playwright/test').Page, username: string) {
  await page.getByLabel('Username', { exact: true }).fill(username)
  await page.getByLabel('Password', { exact: true }).fill('console-test-only')
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
}

test('an administrator creates a protected location only after confirmation; analysts can read but not manage', async ({ page }) => {
  await page.goto('dashboard')
  await signIn(page, 'console-admin')
  const nav = page.getByRole('navigation', { name: 'Workspace' })
  await nav.getByRole('link', { name: 'Folder scanning', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Protected locations' })).toBeVisible()
  await expect(page.getByText('No protected location exists yet.', { exact: false })).toBeVisible()
  await expect(page.getByText('No storage protection worker has reported.', { exact: false })).toBeVisible()

  await page.getByRole('link', { name: 'New location' }).click()
  await page.getByLabel('Name', { exact: true }).fill('Acceptance share')
  await page.getByLabel('Service client').selectOption({ label: 'Acceptance integration (console-client)' })
  await page.getByLabel('Scan profile').selectOption({ label: 'Acceptance routing' })
  await page.getByLabel('Storage backend').selectOption('shared')
  await page.getByLabel('Prefix inside the backend').fill('incoming/client-a')
  // Disabled so the fixture's system health stays unchanged for later specs.
  await page.getByLabel('Enabled', { exact: true }).uncheck()
  let writes = 0
  page.on('request', request => { if (request.method() === 'POST' && request.url().includes('/storage/locations')) writes++ })
  await page.getByRole('button', { name: 'Review' }).click()
  await expect(page.getByRole('dialog')).toContainText('Acceptance share')
  expect(writes).toBe(0)
  await page.getByRole('dialog').getByRole('button', { name: 'Confirm' }).click()
  await expect(page.getByRole('heading', { name: 'Acceptance share' })).toBeVisible()
  expect(writes).toBe(1)
  await expect(page.getByText('This location is disabled.', { exact: false })).toBeVisible()
  await expect(page.getByText('shared:/incoming/client-a')).toBeVisible()
  await page.screenshot({ path: '../artifacts/console-e2e/folder-scanning-location.png', fullPage: true })
  await page.goto('storage/locations/new')
  await expect(page.getByLabel('Name', { exact: true })).toBeVisible()
  await page.screenshot({ path: '../artifacts/console-e2e/folder-scanning-form.png', fullPage: true })

  // Outside the client's grant: refused with a reason, nothing created.
  await page.goto('storage/locations/new')
  await page.getByLabel('Name', { exact: true }).fill('Outside grant')
  await page.getByLabel('Service client').selectOption({ label: 'Acceptance integration (console-client)' })
  await page.getByLabel('Scan profile').selectOption({ label: 'Acceptance routing' })
  await page.getByLabel('Storage backend').selectOption('archive')
  await page.getByRole('button', { name: 'Review' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Confirm' }).click()
  await expect(page.getByRole('alert')).toContainText('storage grant does not cover')

  await page.getByRole('button', { name: 'Sign out' }).click()
  await signIn(page, 'console-analyst')
  await nav.getByRole('link', { name: 'Folder scanning', exact: true }).click()
  await expect(page.getByRole('link', { name: 'Acceptance share' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'New location' })).toHaveCount(0)
  await page.getByRole('link', { name: 'Findings', exact: true }).click()
  await expect(page.getByText('No findings match these filters.')).toBeVisible()
  expect((await page.request.get('/api/ui/v1/storage/options')).status()).toBe(403)
})
