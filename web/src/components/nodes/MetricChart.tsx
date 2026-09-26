import { Area, AreaChart, CartesianGrid, Line, LineChart, XAxis, YAxis } from 'recharts'

import { EmptyState } from '@/components/EmptyState'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from '@/components/ui/chart'
import { Skeleton } from '@/components/ui/skeleton'
import { fmtCompact, fmtDateTime } from '@/lib/format'
import { LuChartArea } from 'react-icons/lu'
import { useId, type ReactNode } from 'react'

import type { MetricRow } from './metrics'

type Key = Exclude<keyof MetricRow, 'ts'>

export interface MetricChartProps {
  title: string
  description?: ReactNode
  action?: ReactNode
  rows: MetricRow[]
  series: { key: Key; label: string; color: string }[]
  kind?: 'area' | 'line'
  unit?: string
  domain?: [number, number]
  loading?: boolean
  /** Window length in seconds, picks the time-axis format. */
  spanS?: number
}

export function MetricChart({ title, description, action, rows, series, kind = 'area', unit = '', domain, loading, spanS = 6 * 3600 }: MetricChartProps) {
  const gid = useId().replace(/:/g, '')
  const config = Object.fromEntries(series.map((s) => [s.key, { label: s.label, color: s.color }])) satisfies ChartConfig
  const tick = (t: number) =>
    new Date(t).toLocaleString(undefined, spanS > 86400 ? { month: 'short', day: 'numeric' } : { hour: '2-digit', minute: '2-digit' })
  const axes = (
    <>
      <CartesianGrid vertical={false} />
      <XAxis dataKey="ts" type="number" scale="time" domain={['dataMin', 'dataMax']} tickFormatter={tick} tickLine={false} axisLine={false} minTickGap={40} />
      <YAxis width={44} tickLine={false} axisLine={false} domain={domain} tickFormatter={(v: number) => fmtCompact(v) + unit} />
      <ChartTooltip
        content={<ChartTooltipContent indicator="line" labelFormatter={(_, p) => fmtDateTime(new Date(Number(p[0]?.payload?.ts)).toISOString())} />}
      />
    </>
  )
  return (
    <Card className="gap-3 py-4">
      <CardHeader className="px-4">
        <CardTitle className="text-sm">{title}</CardTitle>
        {description && <CardDescription className="text-xs">{description}</CardDescription>}
        {action && <CardAction>{action}</CardAction>}
      </CardHeader>
      <CardContent className="px-2">
        {loading && !rows.length ? (
          <Skeleton className="mx-2 h-56" />
        ) : !rows.length ? (
          <EmptyState icon={LuChartArea} title="No data yet" description="Metrics appear once the node sends heartbeats." className="h-56" />
        ) : (
          <ChartContainer config={config} className="aspect-auto h-56 w-full">
            {kind === 'area' ? (
              <AreaChart data={rows} margin={{ left: 0, right: 8, top: 4 }}>
                <defs>
                  {series.map((s) => (
                    <linearGradient key={s.key} id={`${gid}-${s.key}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor={`var(--color-${s.key})`} stopOpacity={0.5} />
                      <stop offset="95%" stopColor={`var(--color-${s.key})`} stopOpacity={0.05} />
                    </linearGradient>
                  ))}
                </defs>
                {axes}
                {series.map((s) => (
                  <Area key={s.key} dataKey={s.key} type="monotone" stroke={`var(--color-${s.key})`} fill={`url(#${gid}-${s.key})`} strokeWidth={1.5} isAnimationActive={false} />
                ))}
              </AreaChart>
            ) : (
              <LineChart data={rows} margin={{ left: 0, right: 8, top: 4 }}>
                {axes}
                {series.map((s) => (
                  <Line key={s.key} dataKey={s.key} type="monotone" stroke={`var(--color-${s.key})`} strokeWidth={1.5} dot={false} isAnimationActive={false} />
                ))}
              </LineChart>
            )}
          </ChartContainer>
        )}
      </CardContent>
    </Card>
  )
}
