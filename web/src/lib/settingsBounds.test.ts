/// <reference types="node" />
// Run: node --test src/**/*.test.ts (from web/)
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import { SETTINGS_BOUNDS } from './settingsBounds.ts'

test('UI settings bounds match the server validation', () => {
  const go = readFileSync(new URL('../../../internal/panel/server/settings.go', import.meta.url), 'utf8')
  const server: Record<string, { min: number; max: number }> = {}
  for (const [, field, lo, hi] of go.matchAll(/!in\(s\.(\w+),\s*([\d*]+),\s*([\d*]+)\)/g)) {
    const snake = field.replace(/(?<!^)([A-Z])/g, '_$1').toLowerCase()
    const num = (e: string) => e.split('*').reduce((a, b) => a * Number(b), 1)
    server[snake] = { min: num(lo), max: num(hi) }
  }
  assert.deepEqual(SETTINGS_BOUNDS, server)
})
