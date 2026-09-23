import { test, expect } from '@playwright/test'

const BLOCKED = '1'.repeat(64), SECOND = '2'.repeat(64)

test('admin maintains the hash list with explicit confirmation and engine readiness', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await page.goto('engines/hash-list')
  await page.getByLabel('Username', { exact: true }).fill('console-admin')
  await page.getByLabel('Password', { exact: true }).fill('console-test-only')
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Hash list' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Hash list' })).toHaveAttribute('aria-current', 'page')
  await expect(page.getByText('No enabled Hash List engine exists')).toBeVisible()

  await page.getByLabel('Target list').selectOption('block')
  await page.getByLabel(/SHA-256 values/).fill(`${BLOCKED}\n${SECOND.toUpperCase()}\n${BLOCKED}`)
  await page.getByLabel(/Note/).fill('<b>Incident 14</b>')
  await page.getByRole('button', { name: 'Review addition' }).click()
  await expect(page.getByRole('dialog')).toContainText('2 unique SHA-256 values')
  await page.getByRole('button', { name: 'Confirm addition' }).click()
  await expect(page.getByText('Added 2 hashes.')).toBeVisible()
  const table = page.getByRole('region', { name: 'Hash list entries' })
  await expect(table.getByText(BLOCKED)).toBeVisible()
  await expect(table.getByText('<b>Incident 14</b>').first()).toBeVisible()
  expect(await table.locator('td b').count()).toBe(0)

  // Already blocked: reported, never silently moved to the allowlist.
  await page.getByLabel('Target list').selectOption('allow')
  await page.getByLabel(/SHA-256 values/).fill(BLOCKED)
  await page.getByRole('button', { name: 'Review addition' }).click()
  await expect(page.getByRole('dialog')).toContainText('does not clear or allow these files')
  await page.getByRole('button', { name: 'Confirm addition' }).click()
  await expect(page.getByText('Added 0 hashes.')).toBeVisible()
  await expect(page.getByRole('status').filter({ hasText: 'already listed' })).toContainText('on the blocklist')

  await page.getByLabel('SHA-256 or note').fill(SECOND)
  await page.getByRole('button', { name: 'Apply filters' }).click()
  await expect(table.getByRole('row')).toHaveCount(2)
  await page.getByRole('button', { name: `Remove ${SECOND}` }).click()
  await page.getByRole('button', { name: 'Confirm removal' }).click()
  await expect(page.getByText(`Removed ${SECOND} from the blocklist.`)).toBeVisible()
  await expect(page.getByText('No hash list entries match these filters.')).toBeVisible()
  await page.getByRole('button', { name: 'Reset filters' }).click()
  await expect(table.getByText(BLOCKED)).toBeVisible()

  await page.setViewportSize({ width: 390, height: 844 })
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
  await page.setViewportSize({ width: 1280, height: 800 })

  // The built-in engine needs only a name, then the readiness warning clears.
  await page.getByRole('link', { name: 'Engines', exact: true }).first().click()
  await page.getByRole('button', { name: 'Add engine' }).click()
  await page.getByRole('button', { name: 'Hash List supported' }).click()
  await page.getByLabel('Deployment name').fill('Hash list acceptance')
  await page.getByRole('button', { name: 'Create deployment' }).click()
  const card = page.locator('article').filter({ hasText: 'Hash list acceptance' })
  await expect(card).toBeVisible()
  await page.getByRole('link', { name: 'Hash list' }).click()
  await expect(page.getByRole('heading', { name: 'Hash list' })).toBeVisible()
  await expect(page.getByText('No enabled Hash List engine exists')).toHaveCount(0)

  // Leave the shared fixture as other scenarios expect it.
  await page.getByRole('link', { name: 'Engines', exact: true }).first().click()
  await card.getByRole('button', { name: 'Remove Hash list acceptance' }).click()
  await page.getByRole('button', { name: 'Remove deployment', exact: true }).click()
  await expect(card).toHaveCount(0)
  expect(errors).toEqual([])
})
