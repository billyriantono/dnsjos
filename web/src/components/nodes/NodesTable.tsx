import { LuServer } from 'react-icons/lu'
import { Link, useNavigate } from 'react-router'

import { DataTable, type Column } from '@/components/DataTable'
import { EmptyState } from '@/components/EmptyState'
import { StatusBadge } from '@/components/StatusBadge'
import { TimeAgo } from '@/components/TimeAgo'
import { Badge } from '@/components/ui/badge'
import type { Node } from '@/lib/api/types'
import { fmtMs, fmtPercent, fmtQps } from '@/lib/format'
import { cn } from '@/lib/utils'
import type { ReactNode } from 'react'

export function SyncBadge({ ok, label }: { ok: boolean; label: string }) {
  return (
    <Badge
      variant="outline"
      className={cn('font-normal', ok ? 'border-success/30 text-success' : 'border-warning/30 bg-warning/10 text-warning')}
    >
      {label} {ok ? 'in sync' : 'pending'}
    </Badge>
  )
}

const columns: (Column<Node> & { full?: boolean })[] = [
  {
    key: 'name',
    header: 'Node',
    sortValue: (n) => n.name,
    cell: (n) => (
      <div className="min-w-0">
        <Link to={`/nodes/${n.id}`} className="font-medium hover:underline" onClick={(e) => e.stopPropagation()}>
          {n.name}
        </Link>
        <div className="truncate text-xs text-muted-foreground">{n.public_ip || n.hostname || '—'}</div>
      </div>
    ),
  },
  { key: 'status', header: 'Status', sortValue: (n) => n.status, cell: (n) => <StatusBadge status={n.status} /> },
  { key: 'qps', header: 'QPS', align: 'right', sortValue: (n) => n.qps, cell: (n) => fmtQps(n.qps) },
  { key: 'hit', header: 'Cache hit', align: 'right', sortValue: (n) => n.cache_hit_ratio, cell: (n) => fmtPercent(n.cache_hit_ratio) },
  { key: 'lat', header: 'Latency', align: 'right', sortValue: (n) => n.latency_avg_ms, cell: (n) => fmtMs(n.latency_avg_ms) },
  {
    key: 'ver',
    header: 'Versions',
    full: true,
    sortValue: (n) => n.dnsdist_version,
    cell: (n) => (
      <div className="text-xs leading-tight">
        <div>dnsdist {n.dnsdist_version || '—'}</div>
        <div className="text-muted-foreground">agent {n.agent_version || '—'}</div>
      </div>
    ),
  },
  {
    key: 'sync',
    header: 'Sync',
    full: true,
    sortValue: (n) => Number(n.config_in_sync) + Number(n.blocklist_in_sync),
    cell: (n) => (
      <div className="flex flex-wrap gap-1">
        <SyncBadge ok={n.config_in_sync} label="config" />
        <SyncBadge ok={n.blocklist_in_sync} label="blocklist" />
      </div>
    ),
  },
  {
    key: 'seen',
    header: 'Last seen',
    sortValue: (n) => n.last_seen_at,
    cell: (n) => <TimeAgo date={n.last_seen_at} className="text-muted-foreground" />,
  },
]

export function NodesTable({
  rows,
  loading,
  error,
  compact,
  empty,
}: {
  rows: Node[] | undefined
  loading?: boolean
  error?: Error | null
  compact?: boolean
  empty?: ReactNode
}) {
  const nav = useNavigate()
  return (
    <DataTable
      columns={compact ? columns.filter((c) => !c.full) : columns}
      rows={rows}
      rowKey={(n) => n.id}
      loading={loading}
      error={error}
      defaultSort={{ key: 'name' }}
      onRowClick={(n) => nav(`/nodes/${n.id}`)}
      empty={empty ?? <EmptyState icon={LuServer} title="No nodes yet" description="Add a node to start monitoring your resolvers." />}
    />
  )
}
