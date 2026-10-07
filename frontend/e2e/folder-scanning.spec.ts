import { test, expect } from '@playwright/test'

async function signIn(page: import('@playwright/test').Page, username: string) {
  await page.getByLabel('Username', { exact: true }).fill(username)
  await page.getByLabel('Password', { exact: true }).fill('console-test-only')
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
}

test('an administrator watches a folder from the client only after confirmation; analysts can read but not manage', async ({ page }) => {
  await page.goto('dashboard')
  await signIn(page, 'console-admin')
  const nav = page.getByRole('navigation', { name: 'Workspace' })
  await expect(nav.getByRole('link', { name: 'Dashboard', exact: true })).toBeVisible()
  // Not in use yet: no worker has reported and no folder is watched.
  await expect(nav.getByRole('link', { name: 'Folder scanning', exact: true })).toHaveCount(0)

  await nav.getByRole('link', { name: 'Service clients', exact: true }).click()
  await page.getByRole('button', { name: 'Manage Acceptance integration' }).click()
  await page.getByRole('tab', { name: 'Storage' }).click()
  const watched = page.getByRole('region', { name: 'Watched folders' })
  await expect(watched).toContainText('No folder is watched for this client.')
  await watched.getByRole('link', { name: 'Watch a folder' }).click()

  await page.getByLabel('Name', { exact: true }).fill('Acceptance share')
  await expect(page.getByLabel('Service client')).toBeDisabled()
  await page.getByLabel('Scan profile').selectOption({ label: 'Acceptance routing' })
  await expect(page.getByRole('link', { name: "Acceptance integration's Scan profiles" })).toBeVisible()
  await page.getByLabel('Storage backend').selectOption('shared')
  await page.getByLabel('Folder inside the backend').fill('incoming/client-a')
  // Disabled so the fixture's system health stays unchanged for later specs.
  await page.getByLabel('Enabled', { exact: true }).uncheck()
  let writes = 0
  page.on('request', request => { if (request.method() === 'POST' && request.url().includes('/storage/locations')) writes++ })
  await page.getByRole('button', { name: 'Review' }).click()
  await expect(page.getByRole('dialog')).toContainText('Acceptance share')
  await expect(page.getByRole('dialog')).toContainText('Rules of Acceptance routing')
  expect(writes).toBe(0)
  await page.getByRole('dialog').getByRole('button', { name: 'Confirm' }).click()
  await expect(page.getByRole('heading', { name: 'Acceptance share' })).toBeVisible()
  expect(writes).toBe(1)
  await expect(page.getByText('This folder is disabled.', { exact: false })).toBeVisible()
  await expect(page.getByText('shared:/incoming/client-a')).toBeVisible()
  await expect(page.getByRole('link', { name: 'Acceptance routing' })).toHaveAttribute('href', /\/service-clients\/1\/profiles$/)
  await page.screenshot({ path: '../artifacts/console-e2e/folder-scanning-location.png', fullPage: true })
  // In use now: the menu shows it.
  await expect(nav.getByRole('link', { name: 'Folder scanning', exact: true })).toBeVisible()
  await page.goto('storage/locations/new?client=1')
  await expect(page.getByLabel('Name', { exact: true })).toBeVisible()
  await page.screenshot({ path: '../artifacts/console-e2e/folder-scanning-form.png', fullPage: true })

  // Outside the client's grant: refused with a reason, nothing created.
  await page.getByLabel('Name', { exact: true }).fill('Outside grant')
  await page.getByLabel('Scan profile').selectOption({ label: 'Acceptance routing' })
  await page.getByLabel('Storage backend').selectOption('archive')
  await page.getByRole('button', { name: 'Review' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Confirm' }).click()
  await expect(page.getByRole('alert')).toContainText('storage grant does not cover')

  await page.getByRole('button', { name: 'Sign out' }).click()
  await signIn(page, 'console-analyst')
  await nav.getByRole('link', { name: 'Folder scanning', exact: true }).click()
  await expect(page.getByRole('link', { name: 'Acceptance share' })).toBeVisible()
  await expect(page.getByRole('link', { name: /New location|Watch a folder/ })).toHaveCount(0)
  await page.getByRole('link', { name: 'Findings', exact: true }).click()
  await expect(page.getByText('No findings match these filters.')).toBeVisible()
  expect((await page.request.get('/api/ui/v1/storage/options')).status()).toBe(403)
})
