import { useState, type ReactNode } from 'react'
import { LuNetwork } from 'react-icons/lu'

import { DataTable, type Column } from '@/components/DataTable'
import { EmptyState } from '@/components/EmptyState'
import { StatusBadge } from '@/components/StatusBadge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { RANGES, useNodeRangeMetrics, type Range } from '@/lib/api/nodes'
import type { BackendStat, NodeLive } from '@/lib/api/types'
import { fmtCompact, fmtDuration, fmtMs, fmtNumber, fmtPercent, fmtQps } from '@/lib/format'

import { MetricChart } from './MetricChart'
import { NodeTopDomainsCard } from './NodeTopDomainsCard'
import { toRows } from './metrics'

type Backend = BackendStat & { share: number }

const backendCols: Column<Backend>[] = [
  {
    key: 'name',
    header: 'Backend',
    sortValue: (b) => b.name || b.address,
    cell: (b) => (
      <div>
        <div className="font-medium">{b.name || b.address}</div>
        {b.name && <div className="font-mono text-xs text-muted-foreground">{b.address}</div>}
      </div>
    ),
  },
  { key: 'state', header: 'State', sortValue: (b) => b.state, cell: (b) => <StatusBadge status={b.state} /> },
  { key: 'weight', header: 'Weight', align: 'right', sortValue: (b) => b.weight, cell: (b) => b.weight },
  { key: 'order', header: 'Order', align: 'right', sortValue: (b) => b.order, cell: (b) => b.order },
  {
    key: 'share',
    header: 'Share',
    align: 'right',
    sortValue: (b) => b.share,
    cell: (b) => (
      <div className="flex items-center justify-end gap-2">
        <div className="h-1.5 w-16 overflow-hidden rounded-full bg-muted">
          <div className="h-full bg-chart-1" style={{ width: `${b.share * 100}%` }} />
        </div>
        <span className="w-12">{fmtPercent(b.share)}</span>
      </div>
    ),
  },
  { key: 'qps', header: 'QPS', align: 'right', sortValue: (b) => b.qps, cell: (b) => fmtQps(b.qps) },
  { key: 'lat', header: 'Latency', align: 'right', sortValue: (b) => b.latency_ms, cell: (b) => fmtMs(b.latency_ms) },
  { key: 'queries', header: 'Queries', align: 'right', sortValue: (b) => b.queries, cell: (b) => fmtCompact(b.queries) },
  { key: 'drops', header: 'Drops', align: 'right', sortValue: (b) => b.drops, cell: (b) => fmtCompact(b.drops) },
]

export function NodeOverviewTab({ id, live, liveLoading }: { id: string; live: NodeLive | undefined; liveLoading: boolean }) {
  const [range, setRange] = useState<Range>('6h')
  const metrics = useNodeRangeMetrics(id, range)
  const rows = toRows(metrics.data)
  const hb = live?.heartbeat
  const totalQps = hb?.backends?.reduce((s, b) => s + b.qps, 0) ?? 0
  const backends = hb?.backends?.map((b) => ({ ...b, share: totalQps ? b.qps / totalQps : 0 }))
  const chart = { rows, loading: metrics.isPending, spanS: RANGES[range] }

  return (
    <div className="space-y-4">
      <Tabs value={range} onValueChange={(v) => setRange(v as Range)} className="gap-4">
        <div className="flex items-center justify-between gap-2">
          <h2 className="text-sm font-medium">Traffic</h2>
          <TabsList aria-label="Time range">
            {Object.keys(RANGES).map((r) => (
              <TabsTrigger key={r} value={r} className="px-3 text-xs">
                {r}
              </TabsTrigger>
            ))}
          </TabsList>
        </div>
        <TabsContent value={range} className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <MetricChart title="Queries per second" {...chart} series={[{ key: 'qps', label: 'QPS', color: 'var(--chart-1)' }]} />
        <MetricChart title="Cache hit ratio" kind="line" unit="%" domain={[0, 100]} {...chart} series={[{ key: 'hit', label: 'Cache hit %', color: 'var(--chart-2)' }]} />
        <MetricChart title="Blocked queries per second" {...chart} series={[{ key: 'blocked', label: 'Blocked/s', color: 'var(--chart-5)' }]} />
        <MetricChart title="Average latency" kind="line" unit=" ms" {...chart} series={[{ key: 'latency', label: 'Latency ms', color: 'var(--chart-3)' }]} />
        </TabsContent>
      </Tabs>

      <h2 className="text-sm font-medium">Backends</h2>
      <DataTable
        columns={backendCols}
        rows={backends}
        rowKey={(b) => b.address}
        loading={liveLoading}
        defaultSort={{ key: 'order' }}
        empty={<EmptyState icon={LuNetwork} title="No backend data" description="Backends appear with the node's next heartbeat." />}
      />

      <NodeTopDomainsCard id={id} />

      {hb && (
        <Card className="gap-2 py-4">
          <CardHeader className="px-4">
            <CardTitle className="text-sm">Host</CardTitle>
          </CardHeader>
          <CardContent className="grid grid-cols-2 gap-3 px-4 text-sm sm:grid-cols-5">
            <Fact label="Agent uptime" value={fmtDuration(hb.uptime_s)} />
            <Fact label="Load (1 min)" value={hb.system.load1.toFixed(2)} />
            <Fact label="Memory free" value={`${fmtNumber(hb.system.mem_avail_mb)} / ${fmtNumber(hb.system.mem_total_mb)} MB`} />
            <Fact label="Disk free" value={`${fmtNumber(hb.system.disk_free_mb)} MB`} />
            <Fact label="OS" value={hb.os || '—'} />
          </CardContent>
        </Card>
      )}
    </div>
  )
}

export function Fact({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="min-w-0">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="tabular truncate font-medium">{value}</div>
    </div>
  )
}
