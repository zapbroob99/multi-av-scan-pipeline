import { test, expect, type Page } from '@playwright/test'

/** Count canvas pixels that are not the scene's dusk ground, so a blank canvas fails. */
async function painted(page: Page) {
  return page.locator('canvas.login-scene').evaluate((canvas: HTMLCanvasElement) => {
    const data = canvas.getContext('2d')!.getImageData(0, 0, canvas.width, canvas.height).data
    let lit = 0
    for (let i = 0; i < data.length; i += 4 * 97) if (data[i] + data[i + 1] + data[i + 2] > 120) lit++
    return lit
  })
}

test('the sign-in scene draws behind the form on wide screens only', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await page.goto('dashboard')
  await expect(page.getByLabel('Username', { exact: true })).toBeFocused()
  const scene = page.locator('canvas.login-scene')
  await expect(scene).toBeVisible()
  await expect(scene).toHaveAttribute('aria-hidden', 'true')
  await expect.poll(() => painted(page), { timeout: 10000 }).toBeGreaterThan(50)
  await page.waitForTimeout(400)
  await page.screenshot({ path: '../artifacts/console-e2e/login-scene-first-theme.png' })
  await page.getByRole('button', { name: /Switch to (light|dark) theme/ }).first().click()
  await page.waitForTimeout(300)
  await page.screenshot({ path: '../artifacts/console-e2e/login-scene-other-theme.png' })

  // The form still works on top of it.
  await page.getByLabel('Username', { exact: true }).fill('console-admin')
  await page.getByLabel('Password', { exact: true }).fill('console-test-only')
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  await expect(page.locator('canvas.login-scene')).toHaveCount(0)
  expect(errors).toEqual([])
})

test('phones get the plain form, without the scene', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto('dashboard')
  await expect(page.getByLabel('Username', { exact: true })).toBeVisible()
  await expect(page.locator('canvas.login-scene')).toBeHidden()
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
})

test('reduced motion gets one still frame', async ({ browser }) => {
  const context = await browser.newContext({ reducedMotion: 'reduce', baseURL: 'http://127.0.0.1:5175/console/' })
  const page = await context.newPage()
  await page.goto('dashboard')
  await expect.poll(() => painted(page), { timeout: 10000 }).toBeGreaterThan(50)
  await context.close()
})
