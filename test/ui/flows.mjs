// Exercises the main UI flows against a panel seeded by fakefleet.go; exits 1 on failure.
//
//	PLAYWRIGHT_CORE=/path/to/node_modules/playwright-core node test/ui/flows.mjs
import { mkdirSync } from 'node:fs'
import { createRequire } from 'node:module'

const { chromium } = createRequire(import.meta.url)(process.env.PLAYWRIGHT_CORE || 'playwright-core')
const BASE = process.env.PANEL || 'http://127.0.0.1:28080'
const OUT = new URL('./screenshots/', import.meta.url).pathname
mkdirSync(OUT, { recursive: true })

const browser = await chromium.launch({ channel: 'chrome' })
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, acceptDownloads: true })
const p = await ctx.newPage()
const errors = []
p.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`))
p.on('console', (m) => m.type() === 'error' && !m.text().includes('401') && errors.push(`console: ${m.text()}`))
p.on('response', (r) => r.status() >= 500 && errors.push(`HTTP ${r.status()} ${r.url()}`))

let failed = 0
async function flow(name, fn) {
  try {
    await fn()
    console.log(`ok   ${name}`)
  } catch (e) {
    failed++
    console.log(`FAIL ${name}: ${e.message.split('\n')[0]}`)
    await p.screenshot({ path: `${OUT}FAIL-${name}.png` }).catch(() => {})
  }
  await p.keyboard.press('Escape').catch(() => {})
}
const toast = (text) => p.locator('[data-sonner-toast]').filter({ hasText: text }).first().waitFor({ timeout: 10000 })
const shot = (name) => p.screenshot({ path: `${OUT}flow-${name}.png` })

await flow('login', async () => {
  await p.goto(BASE + '/login')
  await p.getByLabel(/email/i).fill('admin@example.com')
  await p.getByLabel(/password/i).fill('wrong-password')
  await p.getByRole('button', { name: /sign in/i }).click()
  await p.getByRole('alert').or(p.getByText(/invalid|incorrect|wrong/i)).first().waitFor({ timeout: 5000 })
  await shot('login-error')
  await p.getByLabel(/password/i).fill('admin-pass-1')
  await p.getByRole('button', { name: /sign in/i }).click()
  await p.waitForURL(BASE + '/')
})

await flow('enrollment-token', async () => {
  await p.goto(BASE + '/nodes')
  await p.getByRole('button', { name: /add node/i }).click()
  await p.getByLabel('Node name').fill('dns4')
  await p.getByLabel('Labels').fill('site=sub\nrole=spare')
  await p.getByRole('button', { name: /create token/i }).click()
  await p.getByText(/install\.sh/).first().waitFor()
  await shot('enrollment-token')
  await p.getByRole('button', { name: 'Done' }).click()
})

await flow('profile-save-publish-diff', async () => {
  await p.goto(BASE + '/profiles')
  await p.getByRole('link', { name: 'default' }).click()
  await p.getByRole('tab', { name: 'Cache', exact: true }).click()
  const num = p.getByRole('tabpanel').getByRole('spinbutton').first()
  await num.fill(String(Number(await num.inputValue()) + 1))
  await p.getByText('Unsaved changes').first().waitFor()
  await shot('profile-dirty')
  await p.getByRole('button', { name: /save draft/i }).first().click()
  await p.getByLabel('What changed?').fill('bump cache size (UI test)')
  await p.getByRole('dialog').getByRole('button', { name: /save draft/i }).click()
  const v = Number((await p.locator('[data-sonner-toast]').filter({ hasText: /Saved as draft v\d+/ }).first().textContent()).match(/v(\d+)/)[1])
  await p.getByRole('button', { name: 'Publish' }).first().click()
  await p.getByRole('alertdialog').getByRole('button', { name: 'Publish' }).click()
  await toast(`v${v} published`)
  await p.getByRole('button', { name: new RegExp(`Diff v${v - 1} .*v${v}`) }).click()
  await p.getByRole('dialog').getByText(/cache/i).first().waitFor()
  await p.waitForTimeout(500)
  await shot('profile-diff')
})

await flow('build-now-and-lookup', async () => {
  await p.goto(BASE + '/blocklist')
  await p.getByRole('button', { name: /build now/i }).click()
  await toast(/build/i)
  await p.getByRole('textbox', { name: /lookup|domain/i }).fill('www.bad.example')
  await p.getByRole('button', { name: 'Check' }).click()
  await p.getByText(/is blocked|blocked by/i).first().waitFor()
  await shot('lookup-blocked')
  await p.getByRole('textbox', { name: /lookup|domain/i }).fill('good.example')
  await p.getByRole('button', { name: 'Check' }).click()
  await p.getByText(/not blocked/i).first().waitFor()
})

await flow('report-presets-and-csv', async () => {
  await p.goto(BASE + '/reports')
  for (const preset of ['Last 30 days', 'This month', 'Last month', 'Last year', 'This year']) {
    await p.getByRole('combobox', { name: 'Period' }).click()
    await p.getByRole('option', { name: preset }).click()
    await p.waitForLoadState('networkidle')
    const total = await p.getByText('Blocked queries').first().locator('xpath=../..').textContent()
    if (!/\d/.test(total)) throw new Error(`${preset}: no total`)
    if (preset === 'Last year') await shot('reports-last-year')
  }
  for (const a of await p.getByRole('link', { name: /CSV/ }).all()) {
    const r = await p.request.get(new URL(await a.getAttribute('href'), BASE).href)
    const ct = r.headers()['content-type'] || ''
    if (r.status() !== 200 || !ct.includes('csv')) throw new Error(`CSV ${await a.textContent()}: ${r.status()} ${ct}`)
    if ((await r.text()).split('\n').length < 2) throw new Error(`CSV ${await a.textContent()} empty`)
  }
})

await flow('create-user', async () => {
  await p.goto(BASE + '/users')
  await p.getByRole('button', { name: /add user/i }).click()
  const d = p.getByRole('dialog')
  await d.getByLabel('Email').fill(`viewer${Date.now() % 10000}@example.com`)
  await d.getByLabel('Name').fill('Night shift')
  await d.getByLabel('Password').fill('viewer-pass-1')
  await d.getByRole('button', { name: /create user/i }).click()
  await p.getByRole('cell', { name: /Night shift/ }).first().waitFor()
  await shot('user-created')
})

await flow('change-settings', async () => {
  await p.goto(BASE + '/settings')
  const f = p.getByLabel('Metrics')
  const old = await f.inputValue()
  await f.fill('40')
  await p.getByRole('button', { name: /save settings/i }).click()
  await toast('Settings saved')
  await p.reload()
  if ((await p.getByLabel('Metrics').inputValue()) !== '40') throw new Error('setting not persisted')
  await p.getByLabel('Metrics').fill(old)
  await p.getByRole('button', { name: /save settings/i }).click()
  await toast('Settings saved')
})

await flow('node-command', async () => {
  await p.goto(BASE + '/nodes')
  await p.getByRole('link', { name: 'dns2' }).click()
  await p.getByRole('tab', { name: 'Actions' }).click()
  await p.getByRole('button', { name: /reapply/i }).first().click()
  const confirm = p.getByRole('alertdialog')
  if (await confirm.isVisible().catch(() => false)) await confirm.getByRole('button', { name: /reapply|confirm/i }).last().click()
  await toast(/queued|sent|reapply/i)
  await shot('node-command')
})

await browser.close()
if (errors.length) console.log(errors.join('\n'))
process.exit(failed || errors.length ? 1 : 0)
