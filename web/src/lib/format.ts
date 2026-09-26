const compact = new Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 })
const plain = new Intl.NumberFormat('en')

const bad = (n: number | null | undefined): n is null | undefined => n == null || !Number.isFinite(n)

/** 1234567 → "1.2M" */
export const fmtCompact = (n: number | null | undefined) => (bad(n) ? '—' : compact.format(n))

/** 1234567 → "1,234,567" */
export const fmtNumber = (n: number | null | undefined) => (bad(n) ? '—' : plain.format(n))

/** Ratio 0..1 → "93.4%" */
export const fmtPercent = (ratio: number | null | undefined, digits = 1) =>
  bad(ratio) ? '—' : `${(ratio * 100).toFixed(digits)}%`

export function fmtBytes(n: number | null | undefined) {
  if (bad(n)) return '—'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let i = 0
  while (Math.abs(n) >= 1024 && i < units.length - 1) {
    n /= 1024
    i++
  }
  return `${i === 0 ? n : n.toFixed(n < 10 ? 2 : 1)} ${units[i]}`
}

/** Seconds → "3d 4h", "12m 5s", "42s" (two largest units). */
export function fmtDuration(seconds: number | null | undefined) {
  if (bad(seconds)) return '—'
  let s = Math.max(0, Math.round(seconds))
  const parts: string[] = []
  for (const [u, d] of [['d', 86400], ['h', 3600], ['m', 60], ['s', 1]] as const) {
    if (s >= d || (u === 's' && parts.length === 0)) {
      parts.push(`${Math.floor(s / d)}${u}`)
      s %= d
    }
  }
  return parts.slice(0, 2).join(' ')
}

/** Queries per second → "1.2k qps" */
export const fmtQps = (n: number | null | undefined) =>
  bad(n) ? '—' : `${n < 10 ? n.toFixed(1) : compact.format(n)} qps`

export const fmtMs = (n: number | null | undefined) => (bad(n) ? '—' : `${n < 10 ? n.toFixed(2) : n.toFixed(0)} ms`)

/** "2 min ago" / "in 3 h" */
export function fmtAgo(iso: string | null | undefined, now = Date.now()) {
  if (!iso) return 'never'
  const t = new Date(iso).getTime()
  if (Number.isNaN(t)) return '—'
  const diff = (t - now) / 1000
  const abs = Math.abs(diff)
  const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto', style: 'short' })
  if (abs < 45) return diff < 0 ? 'just now' : 'in a moment'
  for (const [unit, sec] of [['day', 86400], ['hour', 3600], ['minute', 60]] as const)
    if (abs >= sec) return rtf.format(Math.round(diff / sec), unit)
  return rtf.format(Math.round(diff), 'second')
}

export const fmtDateTime = (iso: string | null | undefined) =>
  iso ? new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—'

export const shortSha = (sha: string | null | undefined) => (sha ? sha.slice(0, 12) : '—')
