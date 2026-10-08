import { test, expect } from '@playwright/test'

const FILE = '3'.repeat(64)

test('admin adds and revokes an exception with explicit confirmation', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await page.goto(`engines/exceptions?add=${FILE.toUpperCase()}`)
  await page.getByLabel('Username', { exact: true }).fill('console-admin')
  await page.getByLabel('Password', { exact: true }).fill('console-test-only')
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Exceptions' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Exceptions' })).toHaveAttribute('aria-current', 'page')
  await expect(page.getByLabel('SHA-256', { exact: true })).toHaveValue(FILE)

  await page.getByLabel('Reason', { exact: true }).fill('<b>Ticket 41</b> signed vendor build')
  await page.getByLabel('Expires').selectOption('30')
  await page.getByRole('button', { name: 'Review exception' }).click()
  await expect(page.getByRole('dialog')).toContainText('All clients and manual scans')
  await page.getByRole('button', { name: 'Confirm exception' }).click()
  await expect(page.getByText(/Exception #\d+ added/)).toBeVisible()
  const table = page.getByRole('region', { name: 'Exceptions' })
  await expect(table.getByText(FILE)).toBeVisible()
  await expect(table.getByText('<b>Ticket 41</b> signed vendor build')).toBeVisible()
  expect(await table.locator('td b').count()).toBe(0)

  await page.setViewportSize({ width: 390, height: 844 })
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
  await page.setViewportSize({ width: 1280, height: 800 })

  await table.getByRole('button', { name: /Revoke exception/ }).first().click()
  await page.getByRole('button', { name: 'Confirm revocation' }).click()
  await expect(page.getByText(/Exception #\d+ revoked/)).toBeVisible()
  await expect(page.getByText('No exceptions match these filters.')).toBeVisible()
  await page.getByLabel('State').selectOption('revoked')
  await page.getByRole('button', { name: 'Apply filters' }).click()
  await expect(table.getByText(FILE)).toBeVisible()
  await expect(table.getByRole('button', { name: /Revoke exception/ })).toHaveCount(0)
  expect(errors).toEqual([])
})
