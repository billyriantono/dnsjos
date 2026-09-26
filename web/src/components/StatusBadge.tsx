import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

export type Status = 'online' | 'degraded' | 'offline' | 'pending' | 'up' | 'down' | (string & {})

const tone: Record<string, string> = {
  online: 'bg-success/15 text-success border-success/30',
  up: 'bg-success/15 text-success border-success/30',
  ok: 'bg-success/15 text-success border-success/30',
  degraded: 'bg-warning/15 text-warning border-warning/30',
  warning: 'bg-warning/15 text-warning border-warning/30',
  running: 'bg-info/15 text-info border-info/30',
  paused: 'bg-warning/15 text-warning border-warning/30',
  done: 'bg-success/15 text-success border-success/30',
  offline: 'bg-destructive/15 text-destructive border-destructive/30',
  down: 'bg-destructive/15 text-destructive border-destructive/30',
  failed: 'bg-destructive/15 text-destructive border-destructive/30',
  blocked: 'bg-destructive/15 text-destructive border-destructive/30',
}

/** Coloured status pill; unknown statuses (pending, skipped, …) render neutral. */
export function StatusBadge({ status, label, className }: { status: Status; label?: string; className?: string }) {
  const key = status.toLowerCase()
  return (
    <Badge variant="outline" className={cn('gap-1.5 font-medium capitalize', tone[key] ?? 'text-muted-foreground', className)}>
      <span className={cn('size-1.5 rounded-full bg-current', (key === 'online' || key === 'up' || key === 'running') && 'animate-pulse')} />
      {label ?? status}
    </Badge>
  )
}
