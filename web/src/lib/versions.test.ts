/// <reference types="node" />
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { needsRollForward } from './versions.ts'

test('only versions older than the live one need a roll-forward', () => {
  assert.equal(needsRollForward(1, 2), true)
  assert.equal(needsRollForward(3, 2), false) // newer draft: publish in place
  assert.equal(needsRollForward(1, null), false) // nothing live yet
})
