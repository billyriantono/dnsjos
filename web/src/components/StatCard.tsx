import type { ReactNode } from 'react'
import type { IconType } from 'react-icons'
import { LuTrendingDown, LuTrendingUp } from 'react-icons/lu'

import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'

export interface StatCardProps {
  title: string
  value: ReactNode
  icon?: IconType
  hint?: ReactNode
  /** Relative change, e.g. 0.12 = +12%. Colour follows `trendGood`. */
  trend?: number
  trendGood?: 'up' | 'down'
  loading?: boolean
  className?: string
}

export function StatCard({ title, value, icon: Icon, hint, trend, trendGood = 'up', loading, className }: StatCardProps) {
  const up = (trend ?? 0) >= 0
  const good = up === (trendGood === 'up')
  return (
    <Card className={cn('gap-0 py-4', className)}>
      <CardContent className="px-4">
        <div className="flex items-center justify-between gap-2">
          <span className="text-xs font-medium tracking-wide text-muted-foreground uppercase">{title}</span>
          {Icon && (
            <span className="flex size-7 items-center justify-center rounded-md bg-primary/10 text-primary">
              <Icon className="size-4" />
            </span>
          )}
        </div>
        {loading ? (
          <Skeleton className="mt-2 h-8 w-24" />
        ) : (
          <div className="tabular mt-1 text-2xl font-semibold tracking-tight">{value}</div>
        )}
        {(hint || trend !== undefined) && (
          <div className="mt-1 flex items-center gap-2 text-xs text-muted-foreground">
            {trend !== undefined && Number.isFinite(trend) && (
              <span className={cn('inline-flex items-center gap-0.5 font-medium', good ? 'text-success' : 'text-destructive')}>
                {up ? <LuTrendingUp className="size-3.5" /> : <LuTrendingDown className="size-3.5" />}
                {Math.abs(trend * 100).toFixed(1)}%
              </span>
            )}
            {hint && <span className="truncate">{hint}</span>}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
