// Screenshots every page (light/dark × desktop/mobile) of a panel seeded by fakefleet.go and
// reports console errors, failed requests and horizontal overflow.
//
//	PLAYWRIGHT_CORE=/path/to/node_modules/playwright-core node test/ui/shots.mjs [filter]
import { mkdirSync } from 'node:fs'
import { createRequire } from 'node:module'

const { chromium } = createRequire(import.meta.url)(process.env.PLAYWRIGHT_CORE || 'playwright-core')
const BASE = process.env.PANEL || 'http://127.0.0.1:28080'
const OUT = new URL('./screenshots/', import.meta.url).pathname
const only = process.argv[2]
mkdirSync(OUT, { recursive: true })

const browser = await chromium.launch({ channel: 'chrome' })
const problems = []

// Each step: [name, path, optional action run after load]. Actions open tabs/dialogs.
const tab = (name) => (p) => p.getByRole('tab', { name, exact: true }).first().click()
const btn = (name) => (p) => p.getByRole('button', { name }).first().click()
async function firstNode(p) {
  await p.goto(BASE + '/nodes')
  await p.getByRole('link', { name: 'dns1' }).first().click()
  await p.waitForURL(/\/nodes\/[0-9a-f-]{36}/)
}
async function defaultProfile(p) {
  await p.goto(BASE + '/profiles')
  await p.getByRole('link', { name: 'default' }).first().click()
  await p.waitForURL(/\/profiles\/[0-9a-f-]{36}/)
}
const steps = [
  ['overview', '/'],
  ['nodes', '/nodes'],
  ['nodes-add', '/nodes', btn(/add node/i)],
  ['node-overview', firstNode],
  ['node-abuse', firstNode, tab(/^Abuse/)],
  ['node-cgk', firstNode, tab('CGK')],
  ['node-config', firstNode, tab('Config')],
  ['node-actions', firstNode, tab('Actions')],
  ['profiles', '/profiles'],
  ['profiles-new', '/profiles', btn(/new profile/i)],
  ...['Listeners', 'ACL', 'Upstreams', 'Cache', 'Blocking', 'Abuse', 'CGK', 'Tuning'].map((t) => [
    'profile-' + t.toLowerCase(),
    defaultProfile,
    tab(t),
  ]),
  ['profile-preview', defaultProfile, btn(/preview/i)],
  ['profile-diff', defaultProfile, btn(/^Diff v/)],
  ['profile-load', defaultProfile, btn(/^Load v1$/)],
  ['blocklist', '/blocklist'],
  ['reports', '/reports'],
  ['offenders', '/offenders'],
  ['users', '/users'],
  ['users-new', '/users', btn(/(add|new|create) user/i)],
  ['audit', '/audit'],
  ['settings', '/settings'],
  ['notfound', '/nope'],
]

for (const theme of ['light', 'dark'])
  for (const [vw, vh, tag] of [
    [1440, 900, 'desktop'],
    [390, 844, 'mobile'],
  ]) {
    const ctx = await browser.newContext({ viewport: { width: vw, height: vh }, colorScheme: theme })
    await ctx.addInitScript((t) => localStorage.setItem('dnsjos-theme', t), theme)
    const p = await ctx.newPage()
    let cur = ''
    // The SPA probes /auth/me before login; that 401 (and its console echo) is expected.
    const expected = (t) => cur.startsWith('login') && t.includes('401')
    p.on('console', (m) => ['error', 'warning'].includes(m.type()) && !expected(m.text()) && problems.push(`${cur} console.${m.type()}: ${m.text()}`))
    p.on('pageerror', (e) => problems.push(`${cur} pageerror: ${e.message}`))
    p.on('response', (r) => r.status() >= 400 && !expected(String(r.status())) && problems.push(`${cur} HTTP ${r.status()} ${r.request().method()} ${r.url()}`))

    cur = `login-${theme}-${tag}`
    await p.goto(BASE + '/login')
    await p.waitForTimeout(400)
    if (!only || cur.includes(only)) await p.screenshot({ path: `${OUT}${cur}.png` })
    await p.getByLabel(/email/i).fill('admin@example.com')
    await p.getByLabel(/password/i).fill('admin-pass-1')
    await p.getByRole('button', { name: /sign in/i }).click()
    await p.waitForURL(BASE + '/')

    for (const [name, where, act] of steps) {
      cur = `${name}-${theme}-${tag}`
      if (only && !cur.includes(only)) continue
      try {
        if (typeof where === 'string') await p.goto(BASE + where)
        else await where(p)
        await p.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {})
        if (act) await act(p)
        await p.waitForTimeout(900) // charts animate / skeletons settle
        const over = await p.evaluate(() => document.documentElement.scrollWidth - innerWidth)
        if (over > 0) problems.push(`${cur} horizontal overflow ${over}px`)
        await p.screenshot({ path: `${OUT}${cur}.png`, fullPage: true })
      } catch (e) {
        problems.push(`${cur} step failed: ${e.message.split('\n')[0]}`)
      }
      await p.keyboard.press('Escape').catch(() => {})
    }
    await ctx.close()
  }
await browser.close()
console.log(problems.length ? problems.join('\n') : 'no problems')
