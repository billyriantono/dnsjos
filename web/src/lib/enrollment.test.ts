/// <reference types="node" />
import assert from 'node:assert/strict'
import { test } from 'node:test'

import type { EnrollmentToken } from './api/types.ts'
import { pendingTokens } from './enrollment.ts'

const tok = (id: string, expires_at: string, used_at: string | null = null): EnrollmentToken => ({
  id,
  node_name: '',
  labels: {},
  profile_id: null,
  created_by: null,
  created_at: '2026-01-01T00:00:00Z',
  expires_at,
  used_at,
  used_by_node: null,
})

test('pendingTokens keeps only unused, unexpired tokens', () => {
  const now = Date.parse('2026-01-02T00:00:00Z')
  const got = pendingTokens(
    [tok('open', '2026-01-03T00:00:00Z'), tok('used', '2026-01-03T00:00:00Z', '2026-01-01T12:00:00Z'), tok('expired', '2026-01-01T23:59:59Z')],
    now,
  )
  assert.deepEqual(got.map((t) => t.id), ['open'])
})
