import { useEffect, useState } from 'react'

import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { fmtAgo, fmtDateTime } from '@/lib/format'

/** Relative time that re-renders every 30 s, full timestamp on hover. */
export function TimeAgo({ date, className }: { date: string | null | undefined; className?: string }) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 30_000)
    return () => clearInterval(t)
  }, [])
  if (!date) return <span className={className}>never</span>
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <time dateTime={date} className={className}>
          {fmtAgo(date, now)}
        </time>
      </TooltipTrigger>
      <TooltipContent>{fmtDateTime(date)}</TooltipContent>
    </Tooltip>
  )
}
