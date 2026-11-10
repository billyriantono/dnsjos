/// <reference types="node" />
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { canStartBlocklistBuild } from './blocklistScope.ts'

test('blocklist builds require an explicit scope, not the all-profiles view', () => {
  assert.equal(canStartBlocklistBuild(undefined), false)
  assert.equal(canStartBlocklistBuild(''), true)
  assert.equal(canStartBlocklistBuild('profile-id'), true)
})
