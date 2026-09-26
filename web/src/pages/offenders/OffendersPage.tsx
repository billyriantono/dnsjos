import { useState } from 'react'
import { LuShieldCheck, LuSiren } from 'react-icons/lu'
import { Link } from 'react-router'

import { DataTable, type Column } from '@/components/DataTable'
import { EmptyState } from '@/components/EmptyState'
import { NodeSelect } from '@/components/ops/NodeSelect'
import { PageHeader } from '@/components/PageHeader'
import { StatusBadge } from '@/components/StatusBadge'
import { TimeAgo } from '@/components/TimeAgo'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useOffenders } from '@/lib/api/client'
import type { Offender } from '@/lib/api/types'
import { fmtDuration, fmtNumber } from '@/lib/format'

const columns: Column<Offender>[] = [
  { key: 'client', header: 'Client', sortValue: (o) => o.client, cell: (o) => <code className="font-mono text-xs">{o.client}</code> },
  {
    key: 'node',
    header: 'Node',
    sortValue: (o) => o.node_name,
    cell: (o) => (
      <Link to={`/nodes/${o.node_id}`} className="hover:underline">
        {o.node_name}
      </Link>
    ),
  },
  {
    key: 'stage',
    header: 'Stage',
    sortValue: (o) => o.stage,
    cell: (o) => (
      <div className="flex items-center gap-1.5">
        <StatusBadge status={o.stage} />
        {o.closed && <Badge variant="outline" className="text-muted-foreground">ended</Badge>}
      </div>
    ),
  },
  {
    key: 'reason',
    header: 'Reason',
    sortValue: (o) => o.reason,
    className: 'max-w-72',
    cell: (o) => (
      <span className="block truncate" title={o.reason}>
        {o.reason || '—'}
      </span>
    ),
  },
  { key: 'blocks', header: 'Blocks', align: 'right', sortValue: (o) => o.blocks, cell: (o) => fmtNumber(o.blocks) },
  { key: 'first', header: 'First seen', sortValue: (o) => o.first_seen, cell: (o) => <TimeAgo date={o.first_seen} /> },
  { key: 'last', header: 'Last seen', sortValue: (o) => o.last_seen, cell: (o) => <TimeAgo date={o.last_seen} /> },
  {
    key: 'dur',
    header: 'Duration',
    align: 'right',
    sortValue: (o) => new Date(o.last_seen).getTime() - new Date(o.first_seen).getTime(),
    cell: (o) => fmtDuration((new Date(o.last_seen).getTime() - new Date(o.first_seen).getTime()) / 1000),
  },
]

export default function OffendersPage() {
  const [tab, setTab] = useState<'active' | 'all'>('active')
  const [nodeId, setNodeId] = useState('')
  const active = tab === 'active'
  const { data, isPending, error } = useOffenders({ active: active || undefined, node_id: nodeId || undefined })
  return (
    <>
      <PageHeader
        title="Offenders"
        description="Clients rate-limited by the dynamic block rules (query rate, NXDOMAIN, SERVFAIL). Events close after 10 minutes unseen."
        actions={<NodeSelect value={nodeId} onChange={setNodeId} />}
      />
      <Tabs value={tab} onValueChange={(v) => setTab(v as 'active' | 'all')}>
        <TabsList>
          <TabsTrigger value="active">
            Active
            {active && data && <Badge variant="secondary" className="ml-1">{data.total}</Badge>}
          </TabsTrigger>
          <TabsTrigger value="all">Active + history</TabsTrigger>
        </TabsList>
        {/* One panel for both tabs: only the filter differs. */}
        <TabsContent value={tab}>
          <DataTable
            columns={columns}
            rows={data?.items}
            loading={isPending}
            error={error}
            rowKey={(o) => o.id}
            defaultSort={{ key: 'last', desc: true }}
            skeletonRows={8}
            empty={
              active ? (
                <EmptyState icon={LuShieldCheck} title="No active offenders" description="No client is over the abuse thresholds right now." />
              ) : (
                <EmptyState icon={LuSiren} title="No offender history" />
              )
            }
          />
        </TabsContent>
      </Tabs>
    </>
  )
}
