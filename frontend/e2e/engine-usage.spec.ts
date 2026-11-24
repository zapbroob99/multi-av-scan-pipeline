import { test, expect } from '@playwright/test'

test('admin follows an engine reference to the exact client profile', async ({ page }) => {
  await page.goto('engines')
  await page.getByLabel('Username', { exact: true }).fill('console-admin')
  await page.getByLabel('Password', { exact: true }).fill('console-test-only')
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  await page.getByRole('button', { name: 'Profiles using Static Metadata', exact: true }).click()
  const dialog = page.getByRole('dialog')
  await expect(dialog.getByRole('heading', { name: 'Profiles using Static Metadata' })).toBeVisible()
  await dialog.getByRole('link', { name: 'Acceptance integration / Acceptance routing' }).click()
  await expect(page).toHaveURL(/service-clients\/\d+\/overview\?profile_id=\d+/)
  await expect(page.getByRole('heading', { name: 'Configuration overview', exact: true })).toBeVisible()
  await expect(page.getByLabel('Profile', { exact: true })).not.toHaveValue('')
  await expect(page.getByText('Acceptance routing', { exact: true }).last()).toBeVisible()
})
