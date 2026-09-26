import type { EnrollmentToken } from './api/types.ts'

/** Tokens that can still enroll a node: not used and not expired. */
export const pendingTokens = (tokens: EnrollmentToken[], now = Date.now()) =>
  tokens.filter((t) => t.used_at === null && new Date(t.expires_at).getTime() > now)
