import type { MetricSeries } from '@/lib/api/types'

export interface MetricRow {
  ts: number
  qps: number
  hit: number // cache hit %, 0..100
  blocked: number // blocked queries per second
  latency: number
}

const round = (n: number, d: number) => Math.round(n * 10 ** d) / 10 ** d

/** Maps server samples (qps and hit ratio are derived server-side) to chart rows. */
export function toRows(m: MetricSeries | undefined): MetricRow[] {
  if (!m) return []
  const step = m.step_s || 60
  return m.points.map((p) => ({
    ts: new Date(p.ts).getTime(),
    qps: round(p.qps, 1),
    hit: round(p.cache_hit_ratio * 100, 1),
    blocked: round(p.blocked / step, 2),
    latency: round(p.latency_avg_ms, 2),
  }))
}
