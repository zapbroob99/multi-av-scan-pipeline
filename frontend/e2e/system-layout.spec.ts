import { test, expect } from '@playwright/test'

const TABS = ['Overview', 'Worker nodes', 'Worker pools', 'Runtime and queue', 'Retention', 'Deferred intake', 'Engines', 'Hash list']

test('the System tab strip stays in place across every tab and Engines lives only under System', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await page.goto('system/overview')
  await page.getByLabel('Username', { exact: true }).fill('console-admin')
  await page.getByLabel('Password', { exact: true }).fill('console-test-only')
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  const strip = page.getByRole('navigation', { name: 'System sections' })
  await expect(strip).toBeVisible()
  const top = (await strip.boundingBox())!.y

  for (const name of TABS) {
    await strip.getByRole('link', { name, exact: true }).click()
    await expect(strip.getByRole('link', { name, exact: true })).toHaveAttribute('aria-current', 'page')
    // One strip, rendered by the shared layout at the same height on every tab.
    await expect(page.getByRole('navigation', { name: 'System sections' })).toHaveCount(1)
    expect((await strip.boundingBox())!.y).toBe(top)
  }

  // Engines is reached from System; the sidebar has no separate entry, and
  // System stays highlighted while an Engines screen is open.
  await expect(page.getByRole('link', { name: 'Engines', exact: true })).toHaveCount(1)
  await expect(page.locator('.sidebar').getByRole('link', { name: 'System', exact: true })).toHaveClass(/active/)
  expect(errors).toEqual([])
})
