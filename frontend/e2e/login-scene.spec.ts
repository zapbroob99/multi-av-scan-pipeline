import { test, expect } from '@playwright/test'

test('the sign-in scene draws behind the form on wide screens only', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await page.goto('dashboard')
  await expect(page.getByLabel('Username', { exact: true })).toBeFocused()
  const scene = page.locator('.login-scene')
  await expect(scene).toBeVisible()
  await expect(scene).toHaveAttribute('aria-hidden', 'true')
  await expect(page.locator('.login-filaments path')).toHaveCount(166)
  await expect(page.locator('.login-engraving')).toBeVisible()
  await page.waitForTimeout(400)
  await page.screenshot({ path: '../artifacts/console-e2e/login-scene-first-theme.png' })
  const ground = await page.locator('.login-main-scene').evaluate(el => getComputedStyle(el).backgroundColor)
  await page.getByRole('button', { name: /Switch to (light|dark) theme/ }).first().click()
  await expect.poll(() => page.locator('.login-main-scene').evaluate(el => getComputedStyle(el).backgroundColor)).not.toBe(ground)
  await page.waitForTimeout(300)
  await page.screenshot({ path: '../artifacts/console-e2e/login-scene-other-theme.png' })

  // The artwork must not interfere with sign-in.
  await page.getByLabel('Username', { exact: true }).fill('console-admin')
  await page.getByLabel('Password', { exact: true }).fill('console-test-only')
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  await expect(page.locator('.login-scene')).toHaveCount(0)
  expect(errors).toEqual([])
})

test('phones get the plain form, without the scene', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto('dashboard')
  await expect(page.getByLabel('Username', { exact: true })).toBeVisible()
  await expect(page.locator('.login-scene')).toBeHidden()
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
})

test('reduced motion keeps the static engraving', async ({ browser }) => {
  const context = await browser.newContext({ reducedMotion: 'reduce', baseURL: 'http://127.0.0.1:5175/console/' })
  const page = await context.newPage()
  await page.goto('dashboard')
  await expect(page.locator('.login-filaments path')).toHaveCount(166)
  await expect(page.locator('.login-engraving')).toBeVisible()
  await context.close()
})
