import { test, expect } from '@playwright/test'

test('an admin sees what a client still needs and where to point it', async ({ page }) => {
  await page.goto('service-clients')
  await page.getByLabel('Username', { exact: true }).fill('console-admin')
  await page.getByLabel('Password', { exact: true }).fill('console-test-only')
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Service clients' })).toBeVisible()

  await page.getByRole('button', { name: 'Manage Acceptance integration' }).click()
  await page.getByRole('tab', { name: 'Connection' }).click()
  await expect(page.getByRole('heading', { name: 'Connect a client' })).toBeVisible()

  // The endpoints an integration is configured with, in one place.
  await expect(page.getByText(/POST http:\/\/.*\/api\/v1\/scans$/)).toBeVisible()
  await expect(page.getByText(/MASP_ICAP_SERVICE_CLIENT_KEY=/)).toBeVisible()
  await expect(page.getByText('Authorization: Bearer <api token>')).toBeVisible()

  // The fixture client has routing but no credential, so readiness must say so
  // rather than implying the integration can already connect.
  await expect(page.getByRole('alert')).toContainText('Not ready')
  await expect(page.getByText('Active API credential')).toBeVisible()

  await expect(page.getByRole('heading', { name: 'Engines this client would run' })).toBeVisible()
  await page.setViewportSize({ width: 1440, height: 960 })
  for (const theme of ['light', 'dark']) {
    await page.getByRole('button', { name: 'Close dialog' }).click()
    const toggle = page.getByRole('button', { name: `Switch to ${theme} theme` })
    if (await toggle.count()) await toggle.click()
    await page.getByRole('button', { name: 'Manage Acceptance integration' }).click()
    await page.getByRole('tab', { name: 'Connection' }).click()
    await expect(page.getByRole('heading', { name: 'Engines this client would run' })).toBeVisible()
    await page.screenshot({ path: `../artifacts/console-e2e/client-setup-${theme}.png`, fullPage: true, animations: 'disabled' })
  }

  await page.setViewportSize({ width: 390, height: 844 })
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
  await page.screenshot({ path: '../artifacts/console-e2e/client-setup-mobile.png', fullPage: true })
  await page.setViewportSize({ width: 1280, height: 800 })

  await page.getByRole('button', { name: 'Close dialog' }).click()
  await expect(page.getByRole('heading', { name: 'Service clients' })).toBeVisible()
})

test('an analyst cannot reach client setup', async ({ page }) => {
  await page.goto('service-clients/1/setup')
  await page.getByLabel('Username', { exact: true }).fill('console-analyst')
  await page.getByLabel('Password', { exact: true }).fill('console-test-only')
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Administrator access required' })).toBeVisible()
})
