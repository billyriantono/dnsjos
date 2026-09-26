import { LuCloud, LuRefreshCw } from 'react-icons/lu'
import { toast } from 'sonner'

import { RequireAdmin } from '@/app/auth'
import { EmptyState } from '@/components/EmptyState'
import { StatusBadge } from '@/components/StatusBadge'
import { TimeAgo } from '@/components/TimeAgo'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useNodeCGK, useNodeCommand } from '@/lib/api/client'
import type { NodeLive } from '@/lib/api/types'

import { Fact } from './NodeOverviewTab'

function Chips({ items, empty }: { items: string[]; empty: string }) {
  if (!items.length) return <p className="text-sm text-muted-foreground">{empty}</p>
  return (
    <div className="flex flex-wrap gap-1.5">
      {items.map((i) => (
        <Badge key={i} variant="secondary" className="font-mono font-normal">
          {i}
        </Badge>
      ))}
    </div>
  )
}

export function NodeCGKTab({ id, live }: { id: string; live: NodeLive | undefined }) {
  const report = useNodeCGK(id)
  const cmd = useNodeCommand()
  const st = live?.heartbeat?.cgk
  const d = report.data
  // Go agents encode empty slices as null.
  const r = d && { ...d, aliases: d.aliases ?? [], rewrite_ranges: d.rewrite_ranges ?? [], pools: d.pools ?? [] }

  const refresh = () =>
    cmd.mutate(
      { id, type: 'cgk_refresh' },
      {
        onSuccess: () => toast.success('CGK refresh queued', { description: 'The agent picks it up on its next heartbeat.' }),
        onError: (e) => toast.error(e.message),
      },
    )

  return (
    <div className="space-y-4">
      <Card className="gap-3 py-4">
        <CardHeader className="px-4">
          <CardTitle className="text-sm">CGK redirection</CardTitle>
          <CardDescription className="text-xs">Rewrites answers in CGK-routed Cloudflare ranges to measured non-CGK aliases.</CardDescription>
          <CardAction>
            <RequireAdmin>
              <Button size="sm" variant="outline" onClick={refresh} disabled={cmd.isPending}>
                <LuRefreshCw className={cmd.isPending ? 'animate-spin' : undefined} /> Refresh now
              </Button>
            </RequireAdmin>
          </CardAction>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-3 px-4 text-sm sm:grid-cols-4">
          <Fact label="Aliases active" value={st?.aliases ?? '—'} />
          <Fact label="Rewrite ranges" value={st?.rewrite_ranges ?? '—'} />
          <Fact label="Last refresh" value={<TimeAgo date={st?.last_refresh ?? r?.measured_at} />} />
          <Fact label="Last result" value={r ? <StatusBadge status={r.ok ? 'ok' : 'failed'} /> : '—'} />
          {(st?.last_error || (r && !r.ok && r.message)) && (
            <p className="col-span-full rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
              {st?.last_error || r?.message}
            </p>
          )}
        </CardContent>
      </Card>

      {report.isPending ? (
        <Skeleton className="h-48" />
      ) : !r ? (
        <Card>
          <EmptyState icon={LuCloud} title="No CGK measurement yet" description="The agent reports after its first refresh (every few hours or on demand)." />
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
          <Card className="gap-3 py-4">
            <CardHeader className="px-4">
              <CardTitle className="text-sm">Aliases ({r.aliases.length})</CardTitle>
              <CardDescription className="text-xs">
                Measured <TimeAgo date={r.measured_at} />
                {r.message && r.ok && ` · ${r.message}`}
              </CardDescription>
            </CardHeader>
            <CardContent className="px-4">
              <Chips items={r.aliases} empty="No aliases selected." />
            </CardContent>
          </Card>
          <Card className="gap-3 py-4">
            <CardHeader className="px-4">
              <CardTitle className="text-sm">Rewrite ranges ({r.rewrite_ranges.length})</CardTitle>
              <CardDescription className="text-xs">Candidate pools currently served from CGK.</CardDescription>
            </CardHeader>
            <CardContent className="px-4">
              <Chips items={r.rewrite_ranges} empty="No ranges need rewriting." />
            </CardContent>
          </Card>
          {r.pools.length > 0 && (
            <Card className="gap-3 py-4 lg:col-span-2">
              <CardHeader className="px-4">
                <CardTitle className="text-sm">Pools sampled</CardTitle>
              </CardHeader>
              <CardContent className="grid gap-2 px-4 sm:grid-cols-2 xl:grid-cols-3">
                {r.pools.map((p) => (
                  <div key={p.net} className="flex items-center justify-between gap-2 rounded-md border px-3 py-2 text-sm">
                    <span className="font-mono">{p.net}</span>
                    <span className="truncate text-xs text-muted-foreground">{p.colos?.join(', ') || '—'}</span>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  )
}
