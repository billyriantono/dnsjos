import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { fmtPercent } from '@/lib/format'

export const APPROX_HINT =
  'Approximate: a contributing node samples queries (counts are scaled up) or the name was in the long tail of a top-K sketch (count may be over-estimated).'

export function ApproxMark() {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="cursor-help text-muted-foreground" aria-label="approximate">
          ≈
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs">{APPROX_HINT}</TooltipContent>
    </Tooltip>
  )
}

export function ShareBar({ ratio, className = 'w-20' }: { ratio: number; className?: string }) {
  return (
    <div className="flex items-center justify-end gap-2">
      <div className={`h-1.5 overflow-hidden rounded-full bg-muted ${className}`}>
        <div className="h-full rounded-full bg-chart-1" style={{ width: `${Math.min(100, ratio * 100)}%` }} />
      </div>
      <span className="tabular w-12 text-right">{fmtPercent(ratio)}</span>
    </div>
  )
}
