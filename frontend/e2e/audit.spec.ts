import { test, expect } from '@playwright/test'

test('admin pages the audit trail with literal search while analysts are refused', async ({ page }) => {
  await page.goto('audit')
  await page.getByLabel('Username', { exact: true }).fill('console-admin')
  await page.getByLabel('Password', { exact: true }).fill('console-test-only')
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Audit trail' })).toBeVisible()
  await expect(page.getByText('audit-fixture-literal')).toBeVisible()
  await page.setViewportSize({ width: 390, height: 844 })
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
  await page.setViewportSize({ width: 1280, height: 800 })

  await page.getByRole('button', { name: 'Older events' }).click()
  await expect(page.getByText('audit-fixture-literal')).toHaveCount(0)
  await page.getByRole('button', { name: 'Newest events' }).click()
  await expect(page.getByText('audit-fixture-literal')).toBeVisible()

  await page.getByLabel('Actor, action, target or request ID').fill('ops%team')
  await page.getByRole('button', { name: 'Apply filters' }).click()
  await expect(page.getByText('audit-fixture-literal')).toBeVisible()
  await expect(page.getByText('audit-fixture-00')).toHaveCount(0)
  await page.getByRole('button', { name: 'Reset filters' }).click()

  await page.getByLabel('Outcome').selectOption('denied')
  await page.getByRole('button', { name: 'Apply filters' }).click()
  await expect(page.getByText('audit-fixture-20')).toBeVisible()
  await expect(page.getByText('audit-fixture-19')).toHaveCount(0)

  // Recorded details stay inert text and are never parsed as markup.
  await page.getByText('Recorded details').first().click()
  await expect(page.locator('pre').first()).toContainText('<script>inert audit fixture</script>')
  expect(await page.locator('pre script').count()).toBe(0)

  await page.getByRole('button', { name: 'Sign out' }).click()
  await expect(page.getByRole('heading', { name: 'Welcome back.' })).toBeVisible()
  await page.getByLabel('Username', { exact: true }).fill('console-analyst')
  await page.getByLabel('Password', { exact: true }).fill('console-test-only')
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  // Still on /console/audit: the analyst session is refused without a reload.
  await expect(page.getByRole('heading', { name: 'Administrator access required' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Audit', exact: true })).toHaveCount(0)
})

test('every operator reads the About snapshot with admin-only counts scoped', async ({ page }) => {
  await page.goto('about')
  await page.getByLabel('Username', { exact: true }).fill('console-analyst')
  await page.getByLabel('Password', { exact: true }).fill('console-test-only')
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'About MASP' })).toBeVisible()
  await expect(page.getByText('Runtime snapshot')).toBeVisible()
  await expect(page.getByRole('term').filter({ hasText: 'Service clients' })).toHaveCount(0)
  await expect(page.getByRole('navigation', { name: 'Primary interfaces' }).getByRole('link', { name: 'Service clients' })).toHaveCount(0)
  await expect(page.getByRole('link', { name: 'Hash scan' })).toBeVisible()
  await page.setViewportSize({ width: 390, height: 844 })
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
  await page.setViewportSize({ width: 1280, height: 800 })

  await page.getByRole('button', { name: 'Sign out' }).click()
  await page.getByLabel('Username', { exact: true }).fill('console-admin')
  await page.getByLabel('Password', { exact: true }).fill('console-test-only')
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  await expect(page.getByRole('term').filter({ hasText: 'Service clients' })).toBeVisible()
  await expect(page.getByRole('navigation', { name: 'Primary interfaces' }).getByRole('link', { name: 'Service clients' })).toBeVisible()
})
