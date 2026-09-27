import type { IconType } from 'react-icons'
import { LuCircleCheck, LuCircleDashed, LuCircleSlash, LuCircleX, LuLoaderCircle, LuPause, LuPlay, LuSquare } from 'react-icons/lu'
import { Link } from 'react-router'
import { toast } from 'sonner'

import { useAuth } from '@/app/auth'
import { ConfirmDialog } from '@/components/ConfirmDialog'
import { UserName } from '@/components/UserName'
import { StatusBadge } from '@/components/StatusBadge'
import { TimeAgo } from '@/components/TimeAgo'
import { toastError } from '@/components/ops/toast'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Skeleton } from '@/components/ui/skeleton'
import { useUpgrade, useUpgradeAction } from '@/lib/api/client'
import type { UpgradeAction, UpgradeRunStep, UpgradeStepStatus } from '@/lib/api/types'
import { fmtDuration } from '@/lib/format'
import { cn } from '@/lib/utils'

const stepIcon: Record<UpgradeStepStatus, [IconType, string]> = {
  pending: [LuCircleDashed, 'text-muted-foreground'],
  running: [LuLoaderCircle, 'animate-spin text-info'],
  ok: [LuCircleCheck, 'text-success'],
  failed: [LuCircleX, 'text-destructive'],
  skipped: [LuCircleSlash, 'text-muted-foreground'],
}

/** Seconds between start and finish, or until `now` while still running. */
const took = (s: UpgradeRunStep, now: number) =>
  s.started_at ? ((s.finished_at ? Date.parse(s.finished_at) : now) - Date.parse(s.started_at)) / 1000 : null

function Step({ s, now, last }: { s: UpgradeRunStep; now: number; last: boolean }) {
  const [Icon, tone] = stepIcon[s.status]
  const secs = took(s, now)
  return (
    <li className="relative flex gap-3 pb-4 last:pb-0">
      {!last && <span className="absolute top-6 bottom-0 left-[9px] w-px bg-border" />}
      <Icon className={cn('mt-0.5 size-5 shrink-0', tone)} />
      <div className="min-w-0 flex-1 space-y-0.5">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <Link to={`/nodes/${s.node_id}`} className="font-medium hover:underline">
            {s.node_name || s.node_id}
          </Link>
          <StatusBadge status={s.status} />
          {(s.from_version || s.to_version) && (
            <span className="font-mono text-xs text-muted-foreground">
              {s.from_version || '?'} → {s.to_version || '?'}
            </span>
          )}
          {secs != null && <span className="tabular text-xs text-muted-foreground">{fmtDuration(secs)}</span>}
        </div>
        {s.message && <p className={cn('text-sm break-words', s.status === 'failed' ? 'text-destructive' : 'text-muted-foreground')}>{s.message}</p>}
      </div>
    </li>
  )
}

const confirms: Record<UpgradeAction, { title: string; text: string; label: string }> = {
  pause: { title: 'Pause this run?', text: 'The node being upgraded finishes its step; no further node starts until you resume.', label: 'Pause' },
  resume: { title: 'Resume this run?', text: 'The panel re-checks node health, retries a failed step and continues with the next node.', label: 'Resume' },
  abort: { title: 'Abort this run?', text: 'Remaining nodes are skipped and stay on their current version. This cannot be resumed.', label: 'Abort run' },
}

/** One upgrade run with its per-node timeline; polls every 3 s while running. */
export function RunCard({ id }: { id: number }) {
  const { isAdmin } = useAuth()
  const q = useUpgrade(id)
  const act = useUpgradeAction()
  const run = q.data
  if (!run) return <Skeleton className="h-48" />

  const done = run.steps.filter((s) => s.status === 'ok' || s.status === 'skipped').length
  const live = run.status === 'running' || run.status === 'paused'
  const actions: UpgradeAction[] = run.status === 'running' ? ['pause', 'abort'] : run.status === 'paused' ? ['resume', 'abort'] : []
  const icons: Record<UpgradeAction, IconType> = { pause: LuPause, resume: LuPlay, abort: LuSquare }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2">
          Run #{run.id}: {run.kind === 'config' ? 'config rollout' : run.kind} →{' '}
          <span className="font-mono">{run.kind === 'config' ? `v${run.target_version}` : run.target_version || 'panel agent'}</span>
          <StatusBadge status={run.status} />
        </CardTitle>
        <CardDescription>
          started <TimeAgo date={run.created_at} />
          {run.created_by && (
            <>
              {' '}
              by <UserName id={run.created_by} />
            </>
          )}
          {run.finished_at && (
            <>
              {' '}
              · finished <TimeAgo date={run.finished_at} />
            </>
          )}
        </CardDescription>
        {isAdmin && live && (
          <CardAction className="flex gap-2">
            {actions.map((a) => {
              const c = confirms[a]
              const Icon = icons[a]
              return (
                <ConfirmDialog
                  key={a}
                  title={c.title}
                  description={c.text}
                  confirmLabel={c.label}
                  destructive={a === 'abort'}
                  onConfirm={() => act.mutateAsync({ id: run.id, action: a }).then(() => toast.success(`Run ${a === 'abort' ? 'aborted' : a + 'd'}`), toastError)}
                >
                  <Button size="sm" variant={a === 'abort' ? 'destructive' : 'outline'}>
                    <Icon /> {c.label.split(' ')[0]}
                  </Button>
                </ConfirmDialog>
              )
            })}
          </CardAction>
        )}
      </CardHeader>
      <CardContent className="space-y-4">
        {run.message && <p className={cn('text-sm', run.status === 'paused' || run.status === 'failed' ? 'text-warning' : 'text-muted-foreground')}>{run.message}</p>}
        <div className="flex items-center gap-3">
          <Progress value={run.steps.length ? (done / run.steps.length) * 100 : 0} className="flex-1" />
          <span className="tabular text-xs text-muted-foreground">
            {done}/{run.steps.length} nodes
          </span>
        </div>
        <ol>
          {run.steps.map((s, i) => (
            <Step key={s.position} s={s} now={q.dataUpdatedAt} last={i === run.steps.length - 1} />
          ))}
        </ol>
      </CardContent>
    </Card>
  )
}
