import type { Node } from '@/lib/api/types'

/** apt series "21" → "2.1" */
export const fmtSeries = (s: string) => (/^\d\d$/.test(s) ? `${s[0]}.${s[1]}` : s || '—')

/** Newest first; Debian version strings compare well enough numerically for dnsdist's scheme. */
export const sortVersions = (vs: string[]) => [...vs].sort((a, b) => b.localeCompare(a, undefined, { numeric: true }))

export const updateAvailable = (n: Pick<Node, 'dnsdist_candidate' | 'dnsdist_version'>) =>
  !!n.dnsdist_candidate && !!n.dnsdist_version && n.dnsdist_candidate !== n.dnsdist_version
