import { LuArrowLeft, LuCircleAlert, LuServerOff } from 'react-icons/lu'
import { Link, useParams } from 'react-router'

import { useAuth } from '@/app/auth'
import { EmptyState } from '@/components/EmptyState'
import { PageHeader } from '@/components/PageHeader'
import { StatCard } from '@/components/StatCard'
import { StatusBadge } from '@/components/StatusBadge'
import { TimeAgo } from '@/components/TimeAgo'
import { NodeAbuseTab } from '@/components/nodes/NodeAbuseTab'
import { NodeActionsTab } from '@/components/nodes/NodeActionsTab'
import { NodeCGKTab } from '@/components/nodes/NodeCGKTab'
import { NodeConfigTab } from '@/components/nodes/NodeConfigTab'
import { NodeOverviewTab } from '@/components/nodes/NodeOverviewTab'
import { SyncBadge } from '@/components/nodes/NodesTable'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ApiError, useNode, useNodeLive } from '@/lib/api/client'
import { fmtMs, fmtPercent, fmtQps, shortSha } from '@/lib/format'

export default function NodeDetailPage() {
  const { id = '' } = useParams()
  const { isAdmin } = useAuth()
  const q = useNode(id)
  const live = useNodeLive(id)
  const node = q.data
  const hb = live.data?.heartbeat

  if (q.isError)
    return (
      <EmptyState
        icon={LuServerOff}
        title={q.error instanceof ApiError && q.error.status === 404 ? 'Node not found' : 'Could not load node'}
        description={q.error.message}
        action={
          <Button asChild variant="outline">
            <Link to="/nodes">Back to nodes</Link>
          </Button>
        }
      />
    )
  if (!node)
    return (
      <div className="space-y-4">
        <Skeleton className="h-12 w-72" />
        <Skeleton className="h-24" />
        <Skeleton className="h-72" />
      </div>
    )

  const errors = [node.last_error, hb?.apply_error, hb?.blocklist_error, hb && !hb.dnsdist_running && 'dnsdist is not running'].filter(
    (e, i, a): e is string => !!e && a.indexOf(e) === i,
  )
  const labels = Object.entries(node.labels ?? {})

  return (
    <>
      <PageHeader
        title={node.name}
        description={
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <StatusBadge status={node.status} />
            <span className="font-mono">{node.public_ip || '—'}</span>
            {node.hostname && <span>{node.hostname}</span>}
            <span>
              profile <b className="font-medium text-foreground">{node.profile_name || '—'}</b>
            </span>
            <span>
              seen <TimeAgo date={node.last_seen_at} />
            </span>
          </span>
        }
        actions={
          <Button asChild variant="ghost" size="sm">
            <Link to="/nodes">
              <LuArrowLeft /> Nodes
            </Link>
          </Button>
        }
      />

      {errors.length > 0 && (
        <div className="flex gap-2 rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
          <LuCircleAlert className="mt-0.5 size-4 shrink-0" />
          <ul className="space-y-0.5">
            {errors.map((e) => (
              <li key={e} className="font-mono text-xs break-all">
                {e}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatCard title="QPS" value={fmtQps(node.qps)} />
        <StatCard title="Cache hit" value={fmtPercent(node.cache_hit_ratio)} />
        <StatCard title="Avg latency" value={fmtMs(node.latency_avg_ms)} />
        <StatCard
          title="Versions"
          value={<span className="text-base">dnsdist {node.dnsdist_version || '—'}</span>}
          hint={`agent ${node.agent_version || '—'} · ${node.os || '—'}`}
        />
      </div>
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        <SyncBadge ok={node.config_in_sync} label="config" />
        <span>
          applied v{node.applied_config_version ?? '—'} / desired v{node.desired_config_version ?? '—'}
        </span>
        <SyncBadge ok={node.blocklist_in_sync} label="blocklist" />
        <span className="font-mono">{shortSha(node.applied_blocklist_sha256)}</span>
        {labels.map(([k, v]) => (
          <Badge key={k} variant="secondary" className="font-normal">
            {k}={v}
          </Badge>
        ))}
      </div>

      <Tabs defaultValue="overview">
        <TabsList className="max-w-full justify-start overflow-x-auto">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="abuse">
            Abuse
            {!!hb?.dynblocks?.length && (
              <Badge variant="destructive" className="h-4 px-1.5 text-[10px]">
                {hb.dynblocks.length}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="cgk">CGK</TabsTrigger>
          <TabsTrigger value="config">Config</TabsTrigger>
          {isAdmin && <TabsTrigger value="actions">Actions</TabsTrigger>}
        </TabsList>
        <TabsContent value="overview" className="mt-2">
          <NodeOverviewTab id={id} live={live.data} liveLoading={live.isPending} />
        </TabsContent>
        <TabsContent value="abuse" className="mt-2">
          <NodeAbuseTab id={id} live={live.data} liveLoading={live.isPending} />
        </TabsContent>
        <TabsContent value="cgk" className="mt-2">
          <NodeCGKTab id={id} live={live.data} />
        </TabsContent>
        <TabsContent value="config" className="mt-2">
          <NodeConfigTab key={node.id} node={node} />
        </TabsContent>
        {isAdmin && (
          <TabsContent value="actions" className="mt-2">
            <NodeActionsTab node={node} />
          </TabsContent>
        )}
      </Tabs>
    </>
  )
}
