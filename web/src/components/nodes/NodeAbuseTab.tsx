import { LuShieldCheck } from 'react-icons/lu'

import { DataTable, type Column } from '@/components/DataTable'
import { EmptyState } from '@/components/EmptyState'
import { StatusBadge } from '@/components/StatusBadge'
import { TimeAgo } from '@/components/TimeAgo'
import { useOffenders } from '@/lib/api/client'
import type { DynBlock, NodeLive, Offender } from '@/lib/api/types'
import { fmtDuration, fmtNumber } from '@/lib/format'

const client = (c: string) => <span className="font-mono">{c}</span>

const dynCols: Column<DynBlock>[] = [
  { key: 'client', header: 'Client', sortValue: (d) => d.client, cell: (d) => client(d.client) },
  { key: 'stage', header: 'Stage', sortValue: (d) => d.stage, cell: (d) => <StatusBadge status={d.stage} /> },
  { key: 'reason', header: 'Reason', sortValue: (d) => d.reason, cell: (d) => d.reason },
  { key: 'left', header: 'Expires in', align: 'right', sortValue: (d) => d.seconds_left, cell: (d) => fmtDuration(d.seconds_left) },
  { key: 'blocks', header: 'Blocked queries', align: 'right', sortValue: (d) => d.blocks, cell: (d) => fmtNumber(d.blocks) },
]

const histCols: Column<Offender>[] = [
  { key: 'client', header: 'Client', sortValue: (o) => o.client, cell: (o) => client(o.client) },
  {
    key: 'stage',
    header: 'Stage',
    sortValue: (o) => o.stage,
    cell: (o) => <StatusBadge status={o.closed ? 'closed' : o.stage} label={o.closed ? `${o.stage} · closed` : o.stage} />,
  },
  { key: 'reason', header: 'Reason', sortValue: (o) => o.reason, cell: (o) => o.reason },
  { key: 'first', header: 'First seen', sortValue: (o) => o.first_seen, cell: (o) => <TimeAgo date={o.first_seen} /> },
  { key: 'last', header: 'Last seen', sortValue: (o) => o.last_seen, cell: (o) => <TimeAgo date={o.last_seen} /> },
  { key: 'blocks', header: 'Blocked queries', align: 'right', sortValue: (o) => o.blocks, cell: (o) => fmtNumber(o.blocks) },
]

export function NodeAbuseTab({ id, live, liveLoading }: { id: string; live: NodeLive | undefined; liveLoading: boolean }) {
  const history = useOffenders({ node_id: id })
  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <h2 className="text-sm font-medium">Active dynamic blocks</h2>
        <DataTable
          columns={dynCols}
          rows={live?.heartbeat ? (live.heartbeat.dynblocks ?? []) : undefined}
          rowKey={(d) => d.client + d.reason}
          loading={liveLoading}
          defaultSort={{ key: 'blocks', desc: true }}
          empty={<EmptyState icon={LuShieldCheck} title="No clients blocked right now" />}
        />
      </div>
      <div className="space-y-2">
        <h2 className="text-sm font-medium">History</h2>
        <DataTable
          columns={histCols}
          rows={history.data?.items}
          rowKey={(o) => o.id}
          loading={history.isPending}
          defaultSort={{ key: 'last', desc: true }}
          empty={<EmptyState icon={LuShieldCheck} title="No abusive clients recorded" />}
        />
      </div>
    </div>
  )
}
