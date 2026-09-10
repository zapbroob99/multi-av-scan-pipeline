import { test, expect } from '@playwright/test'
import { readFile } from 'node:fs/promises'

test('summary/full downloads, analyst retry and admin deletion use the real browser API', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await page.goto('scans/52/manage')
  await page.getByLabel('Username').fill('console-analyst')
  await page.getByLabel('Password').fill('console-test-only')
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'management-retry.txt' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Delete scan' })).toHaveCount(0)
  for (const format of ['JSON', 'CSV']) {
    const downloading = page.waitForEvent('download')
    await page.getByRole('button', { name: `Download summary ${format}` }).click()
    const download = await downloading
    expect(download.suggestedFilename()).toBe(`masp-scan-52-summary.${format.toLowerCase()}`)
    const content = await readFile((await download.path())!, 'utf-8')
    expect(content).toContain('Manual scan summary only')
    expect(content).toContain('management-retry.txt')
    if (format === 'JSON') expect(JSON.parse(content).report.decision.action).toBe('review')
  }
  for (const format of ['JSON', 'CSV']) {
    const downloading = page.waitForEvent('download')
    await page.getByRole('button', { name: `Download full ${format}` }).click()
    const download = await downloading
    expect(download.suggestedFilename()).toBe(`masp-scan-52-full.${format.toLowerCase()}`)
    const content = await readFile((await download.path())!, 'utf-8')
    expect(content).toContain('management-retry.txt')
    if (format === 'JSON') {
      const payload = JSON.parse(content)
      expect(payload.engine_results[0].raw_output).toContain('benign full-export fixture')
      expect(payload.summary.decision.action).toBe('review')
      expect(content).not.toContain('storage_path')
    }
  }
  await page.screenshot({ path: '../artifacts/console-e2e/management-desktop.png', fullPage: true })
  await page.setViewportSize({ width: 390, height: 844 })
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
  await page.screenshot({ path: '../artifacts/console-e2e/management-mobile.png', fullPage: true })
  await page.getByRole('button', { name: 'Retry scan', exact: true }).click()
  await page.getByRole('button', { name: 'Cancel', exact: true }).click()
  await page.getByRole('button', { name: 'Retry scan', exact: true }).click()
  const retry = page.waitForResponse(response => response.url().endsWith('/scans/52/retry'))
  await page.getByRole('button', { name: 'Confirm', exact: true }).click()
  expect((await retry).status()).toBe(202)
  await expect(page.getByText(/Retry accepted/)).toBeVisible()
  await page.getByRole('link', { name: 'Back to report' }).click()
  await expect(page.getByText('Status: queued · Attempt 0')).toBeVisible()
  await page.getByRole('button', { name: 'Sign out' }).click()
  await page.getByLabel('Username').fill('console-admin')
  await page.getByLabel('Password').fill('console-test-only')
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible()
  await page.goto('scans/53/manage')
  await page.getByRole('button', { name: 'Delete scan', exact: true }).click()
  await page.getByRole('button', { name: 'Confirm', exact: true }).click()
  await expect(page.getByText('Scan record deleted. Sample file removed.')).toBeVisible()
  await page.goto('scans/53')
  await expect(page.getByRole('heading', { name: 'Report unavailable' })).toBeVisible()
  expect(errors).toEqual([])
})
