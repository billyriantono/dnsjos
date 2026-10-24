import type { BlocklistProfile } from '@/lib/api/types'

/** Renders a source's / RPZ master's profile set as a label, "Global" when it is shared. */
export function profileSetLabel(names: string[] | undefined): string {
  return names && names.length > 0 ? names.join(', ') : 'Global'
}

/** Two profile sets are equal regardless of order. */
export function sameProfiles(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false
  const sa = [...a].sort()
  const sb = [...b].sort()
  return sa.every((v, i) => v === sb[i])
}

/** The display name of a profile id, falling back to the raw id. */
export function profileLabel(profiles: BlocklistProfile[] | undefined, id: string): string {
  return profiles?.find((p) => p.id === id)?.name ?? id
}
