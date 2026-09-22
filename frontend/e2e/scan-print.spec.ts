import { test, expect, type Page } from '@playwright/test'

async function signIn(page: Page, user = 'console-admin') {
  await page.getByLabel('Username', { exact: true }).fill(user)
  await page.getByLabel('Password', { exact: true }).fill('console-test-only')
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
}

test('an analyst prints a bounded manual report that automation routes refuse', async ({ page }) => {
  await page.goto('scans/25/print')
  await signIn(page, 'console-analyst')
  await expect(page.getByRole('heading', { name: 'Printable report' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Engine results' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Backend policy decision' })).toBeVisible()

  // Recorded output renders as inert text and is bounded for paper.
  await expect(page.getByLabel('Static Metadata raw output text')).toContainText('<script>benign fixture text</script>')
  expect(await page.locator('pre script').count()).toBe(0)
  await expect(page.getByText(/Output truncated for printing/)).toBeVisible()

  await page.setViewportSize({ width: 390, height: 844 })
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
  await page.setViewportSize({ width: 1280, height: 800 })

  // Console chrome is hidden on paper; the report sheet is not.
  await page.emulateMedia({ media: 'print' })
  await expect(page.getByRole('navigation', { name: 'Workspace' })).toBeHidden()
  await expect(page.getByRole('heading', { name: 'Engine results' })).toBeVisible()
  await page.emulateMedia({ media: 'screen' })

  // Legacy /scans/{id}/report had no source scope; the automation route must refuse a manual scan.
  await page.goto('api-ledger/scans/25/print')
  await expect(page.getByRole('alert')).toContainText('Automation scan not found')
})

test('an oversized engine output is downloadable as plain text without the legacy report', async ({ page }) => {
  await page.goto('scans/25')
  await signIn(page)
  await page.getByRole('link', { name: /Full output for/ }).first().click()
  await expect(page.getByRole('heading', { name: 'Full engine output' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'legacy report' })).toHaveCount(0)

  const link = page.getByRole('link', { name: 'Download raw output (plain text)' })
  const href = await link.getAttribute('href')
  const served = await page.request.get(href!)
  expect(served.status()).toBe(200)
  expect(served.headers()['content-type']).toContain('text/plain')
  expect(served.headers()['content-disposition']).toContain('attachment; filename="masp-scan-25-result-')
  const body = await served.text()
  expect(body).toContain('benign fixture text')
  // The download carries the complete recorded output, not the printable preview.
  expect(body.length).toBeGreaterThan(9000)
})
