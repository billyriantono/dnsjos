import { createContext, useContext } from 'react'

import type { SpecErrors } from '@/lib/api/profiles'

export const SpecErrorsContext = createContext<SpecErrors>({})
export const ReadOnlyContext = createContext(false)

/** Server validation messages for one exact field path, e.g. "upstreams.servers[2].weight". */
export const useFieldErrors = (path: string) => useContext(SpecErrorsContext)[path] ?? []

/** Errors for a list field: the list itself plus its items, keyed by item index (-1 = the list). */
export function useListErrors(path: string) {
  const errs = useContext(SpecErrorsContext)
  const out = new Map<number, string[]>()
  for (const [k, msgs] of Object.entries(errs)) {
    const i = k === path ? -1 : k.startsWith(path + '[') ? parseInt(k.slice(path.length + 1), 10) : NaN
    if (!Number.isNaN(i)) out.set(i, msgs)
  }
  return out
}

export const useReadOnly = () => useContext(ReadOnlyContext)

export const TABS = [
  { id: 'listen', label: 'Listeners', keys: ['listen'] },
  { id: 'acl', label: 'ACL', keys: ['acl'] },
  { id: 'upstreams', label: 'Upstreams', keys: ['upstreams'] },
  { id: 'cache', label: 'Cache', keys: ['cache'] },
  { id: 'blocking', label: 'Blocking', keys: ['blocking'] },
  { id: 'abuse', label: 'Abuse', keys: ['abuse'] },
  { id: 'cgk', label: 'CGK', keys: ['cgk'] },
  { id: 'speed_check', label: 'Speed check', keys: ['speed_check'] },
  { id: 'dualstack', label: 'Dual-stack', keys: ['dualstack'] },
  { id: 'analytics', label: 'Analytics', keys: ['analytics'] },
  { id: 'tuning', label: 'Tuning', keys: ['tuning', 'webserver'] },
] as const
export type TabId = (typeof TABS)[number]['id']

/** Tab that owns an error path like "upstreams.servers[1].weight". */
export const tabOf = (path: string): TabId | undefined =>
  TABS.find((t) => (t.keys as readonly string[]).includes(path.split(/[.[]/)[0]))?.id
