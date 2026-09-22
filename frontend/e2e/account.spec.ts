import { test, expect } from '@playwright/test'

test('analyst changes own password, revokes both browser sessions and signs in again', async ({ page, browser }) => {
  // Dedicated fixture account keeps this password change independent of other tests.
  const other = await browser.newContext()
  const second = await other.newPage()
  try {
    for (const tab of [page, second]) {
      await tab.goto('http://127.0.0.1:5175/console/account')
      await tab.getByLabel('Username', { exact: true }).fill('account-analyst')
      await tab.getByLabel('Password', { exact: true }).fill('console-test-only')
      await tab.getByRole('button', { name: 'Sign in', exact: true }).click()
      await expect(tab.getByRole('heading', { name: 'Account', exact: true })).toBeVisible()
    }
    await page.getByLabel('Current password').fill('console-test-only')
    await page.getByLabel('New password', { exact: true }).fill('changed-console-test-only')
    await page.getByLabel('Confirm new password').fill('changed-console-test-only')
    await page.getByRole('button', { name: 'Review password change' }).click()
    await page.setViewportSize({ width: 390, height: 844 })
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
    await page.getByRole('button', { name: 'Cancel' }).click()
    for (const label of ['Current password', 'New password', 'Confirm new password'])
      await expect(page.getByLabel(label, { exact: true })).toHaveValue('')
    await page.getByLabel('Current password').fill('console-test-only')
    await page.getByLabel('New password', { exact: true }).fill('changed-console-test-only')
    await page.getByLabel('Confirm new password').fill('changed-console-test-only')
    await page.getByRole('button', { name: 'Review password change' }).click()
    await page.getByRole('button', { name: 'Confirm password change' }).click()
    await expect(page.getByRole('heading', { name: 'Welcome back.' })).toBeVisible()
    await expect(page.getByRole('status')).toContainText('All your sessions were signed out')
    await second.getByRole('button', { name: 'Check session' }).click()
    await expect(second.getByRole('heading', { name: 'Welcome back.' })).toBeVisible()
    await page.getByLabel('Username', { exact: true }).fill('account-analyst')
    await page.getByLabel('Password', { exact: true }).fill('console-test-only')
    await page.getByRole('button', { name: 'Sign in', exact: true }).click()
    await expect(page.getByRole('alert')).toContainText('Invalid username or password')
    await page.getByLabel('Password', { exact: true }).fill('changed-console-test-only')
    await page.getByRole('button', { name: 'Sign in', exact: true }).click()
    await expect(page.getByRole('heading', { name: 'Account', exact: true })).toBeVisible()
  } finally { await other.close() }
})
