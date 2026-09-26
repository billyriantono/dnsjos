import { useMemo, useState } from 'react'
import { LuCalendarDays, LuDownload, LuFileChartColumn, LuGlobe, LuServer, LuShieldBan } from 'react-icons/lu'
import { Bar, BarChart, CartesianGrid, XAxis, YAxis } from 'recharts'

import { DataTable, type Column } from '@/components/DataTable'
import { EmptyState } from '@/components/EmptyState'
import { NodeSelect } from '@/components/ops/NodeSelect'
import { PageHeader } from '@/components/PageHeader'
import { StatCard } from '@/components/StatCard'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from '@/components/ui/chart'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { api, useBlockedReport } from '@/lib/api/client'
import type { BlockedByNode, CSVKind, TopDomain } from '@/lib/api/types'
import { fmtCompact, fmtNumber, fmtPercent } from '@/lib/format'

const ymd = (d: Date) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`

type Preset = 'last30' | 'thisMonth' | 'lastMonth' | 'thisYear' | 'lastYear' | 'custom'
const PRESETS: Record<Exclude<Preset, 'custom'>, { label: string; range: (now: Date) => [Date, Date] }> = {
  last30: { label: 'Last 30 days', range: (n) => [new Date(n.getFullYear(), n.getMonth(), n.getDate() - 29), n] },
  thisMonth: { label: 'This month', range: (n) => [new Date(n.getFullYear(), n.getMonth(), 1), n] },
  lastMonth: {
    label: 'Last month',
    range: (n) => [new Date(n.getFullYear(), n.getMonth() - 1, 1), new Date(n.getFullYear(), n.getMonth(), 0)],
  },
  thisYear: { label: 'This year', range: (n) => [new Date(n.getFullYear(), 0, 1), n] },
  lastYear: { label: 'Last year', range: (n) => [new Date(n.getFullYear() - 1, 0, 1), new Date(n.getFullYear() - 1, 11, 31)] },
}

/** Every YYYY-MM between from and to, so months without blocks still show as 0. */
function monthsBetween(from: string, to: string) {
  const out: string[] = []
  let [y, m] = from.split('-').map(Number)
  const [ty, tm] = to.split('-').map(Number)
  while ((y < ty || (y === ty && m <= tm)) && out.length < 240) {
    out.push(`${y}-${String(m).padStart(2, '0')}`)
    if (++m > 12) [y, m] = [y + 1, 1]
  }
  return out
}

const monthLabel = (ym: string) =>
  new Date(`${ym}-01T00:00:00`).toLocaleDateString(undefined, { month: 'short', year: '2-digit' })

const chartConfig = { count: { label: 'Blocked', color: 'var(--chart-5)' } } satisfies ChartConfig

export default function ReportsPage() {
  const [preset, setPreset] = useState<Preset>('thisYear')
  const [custom, setCustom] = useState(() => {
    const [f, t] = PRESETS.thisYear.range(new Date())
    return { from: ymd(f), to: ymd(t) }
  })
  const [nodeId, setNodeId] = useState('')
  const [limit, setLimit] = useState(100)

  const { from, to } = useMemo(() => {
    if (preset === 'custom') return custom
    const [f, t] = PRESETS[preset].range(new Date())
    return { from: ymd(f), to: ymd(t) }
  }, [preset, custom])
  const valid = from !== '' && to !== '' && from <= to
  const q = { from, to, node_id: nodeId || undefined, limit }
  const { data, isPending, isFetching, error } = useBlockedReport(q)
  const loading = !valid || isPending

  const days = Math.round((new Date(to).getTime() - new Date(from).getTime()) / 86_400_000) + 1
  const monthly = useMemo(() => {
    const byMonth = new Map(data?.by_month.map((m) => [m.month, m.count]))
    return valid ? monthsBetween(from, to).map((month) => ({ month, count: byMonth.get(month) ?? 0 })) : []
  }, [data, from, to, valid])
  const total = data?.total ?? 0

  const nodeColumns: Column<BlockedByNode>[] = [
    { key: 'node', header: 'Node', sortValue: (r) => r.node_name, cell: (r) => <span className="font-medium">{r.node_name}</span> },
    { key: 'count', header: 'Blocked queries', align: 'right', sortValue: (r) => r.count, cell: (r) => fmtNumber(r.count) },
    {
      key: 'share',
      header: 'Share',
      align: 'right',
      sortValue: (r) => r.count,
      cell: (r) => <ShareBar ratio={total ? r.count / total : 0} />,
    },
  ]
  const top = useMemo(() => data?.top_domains.map((d, i) => ({ ...d, rank: i + 1 })), [data])
  const topColumns: Column<TopDomain & { rank: number }>[] = [
    { key: 'rank', header: '#', sortValue: (r) => r.rank, cell: (r) => <span className="text-muted-foreground">{r.rank}</span> },
    { key: 'qname', header: 'Domain', sortValue: (r) => r.qname, cell: (r) => <code className="font-mono text-xs break-all">{r.qname}</code> },
    { key: 'count', header: 'Blocked queries', align: 'right', sortValue: (r) => r.count, cell: (r) => fmtNumber(r.count) },
    { key: 'share', header: 'Share of total', align: 'right', cell: (r) => fmtPercent(total ? r.count / total : 0, 2) },
  ]

  const csv = (kind: CSVKind, label: string) => (
    <Button key={kind} variant="outline" size="sm" asChild disabled={!valid}>
      <a href={valid ? api.reports.blockedCsvUrl({ ...q, kind }) : undefined} download>
        <LuDownload />
        {label}
      </a>
    </Button>
  )

  return (
    <>
      <PageHeader
        title="Reports"
        description="Blocked-query totals and top blocked domains for the yearly Ministry (Komdigi) report. Export each table as CSV."
        actions={[csv('summary', 'Summary CSV'), csv('monthly', 'Monthly CSV'), csv('top', 'Top domains CSV')]}
      />

      <Card className="py-4">
        <CardContent className="flex flex-wrap items-end gap-3 px-4">
          <div className="grid gap-1.5">
            <span className="text-xs text-muted-foreground">Period</span>
            <Select
              value={preset}
              onValueChange={(v) => {
                if (v === 'custom') setCustom({ from, to })
                setPreset(v as Preset)
              }}
            >
              <SelectTrigger className="w-40" aria-label="Period">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {Object.entries(PRESETS).map(([k, p]) => (
                  <SelectItem key={k} value={k}>
                    {p.label}
                  </SelectItem>
                ))}
                <SelectItem value="custom">Custom range</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <label className="grid gap-1.5">
            <span className="text-xs text-muted-foreground">From</span>
            <Input
              type="date"
              className="w-40"
              value={from}
              max={to}
              onChange={(e) => {
                setCustom({ from: e.target.value, to })
                setPreset('custom')
              }}
            />
          </label>
          <label className="grid gap-1.5">
            <span className="text-xs text-muted-foreground">To</span>
            <Input
              type="date"
              className="w-40"
              value={to}
              min={from}
              onChange={(e) => {
                setCustom({ from, to: e.target.value })
                setPreset('custom')
              }}
            />
          </label>
          <div className="grid gap-1.5">
            <span className="text-xs text-muted-foreground">Node</span>
            <NodeSelect value={nodeId} onChange={setNodeId} />
          </div>
          <div className="grid gap-1.5">
            <span className="text-xs text-muted-foreground">Top domains</span>
            <Select value={String(limit)} onValueChange={(v) => setLimit(Number(v))}>
              <SelectTrigger className="w-28" aria-label="Top domains limit">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {[25, 100, 500, 1000].map((n) => (
                  <SelectItem key={n} value={String(n)}>
                    Top {n}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {!valid && <p className="text-sm text-destructive">“From” must be on or before “To”.</p>}
          {error && <p className="text-sm text-destructive">{error.message}</p>}
          {isFetching && !isPending && <span className="text-xs text-muted-foreground">Updating…</span>}
        </CardContent>
      </Card>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard title="Blocked queries" icon={LuShieldBan} value={fmtNumber(total)} hint={`${from} → ${to}`} loading={loading} />
        <StatCard title="Daily average" icon={LuCalendarDays} value={fmtCompact(days > 0 ? total / days : 0)} hint={`${days} days`} loading={loading} />
        <StatCard title="Nodes reporting" icon={LuServer} value={fmtNumber(data?.by_node.length ?? 0)} loading={loading} />
        <StatCard
          title="Top domain"
          icon={LuGlobe}
          value={<span className="block truncate text-base">{data?.top_domains[0]?.qname ?? '—'}</span>}
          hint={data?.top_domains[0] && `${fmtNumber(data.top_domains[0].count)} queries`}
          loading={loading}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
        <Card className="xl:col-span-3">
          <CardHeader>
            <CardTitle>Blocked per month</CardTitle>
            <CardDescription>Queries answered with the blockpage, summed over {nodeId ? 'the selected node' : 'all nodes'}.</CardDescription>
          </CardHeader>
          <CardContent>
            {loading ? (
              <Skeleton className="h-72 w-full" />
            ) : total === 0 ? (
              <EmptyState icon={LuFileChartColumn} title="No blocked queries in this period" className="h-72" />
            ) : (
              <ChartContainer config={chartConfig} className="aspect-auto h-72 w-full">
                <BarChart data={monthly} margin={{ left: 4, right: 4 }}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="month" tickLine={false} axisLine={false} tickFormatter={monthLabel} minTickGap={8} />
                  <YAxis tickLine={false} axisLine={false} width={48} tickFormatter={(v: number) => fmtCompact(v)} />
                  <ChartTooltip
                    content={
                      <ChartTooltipContent
                        labelFormatter={(v) => monthLabel(String(v))}
                        formatter={(v) => (
                          <span className="tabular font-medium">{fmtNumber(Number(v))} blocked</span>
                        )}
                      />
                    }
                  />
                  <Bar dataKey="count" fill="var(--color-count)" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
        <Card className="xl:col-span-2">
          <CardHeader>
            <CardTitle>Per node</CardTitle>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={nodeColumns}
              rows={valid ? data?.by_node : undefined}
              loading={loading}
              rowKey={(r) => r.node_id}
              defaultSort={{ key: 'count', desc: true }}
              empty={<EmptyState icon={LuServer} title="No node reported blocks" />}
            />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Top blocked domains</CardTitle>
          <CardDescription>Ranked by blocked queries in the selected period.</CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={topColumns}
            rows={valid ? top : undefined}
            loading={loading}
            rowKey={(r) => r.qname}
            defaultSort={{ key: 'rank' }}
            skeletonRows={10}
            empty={<EmptyState icon={LuGlobe} title="No blocked domains" />}
          />
        </CardContent>
      </Card>
    </>
  )
}

function ShareBar({ ratio }: { ratio: number }) {
  return (
    <div className="flex items-center justify-end gap-2">
      <div className="h-1.5 w-20 overflow-hidden rounded-full bg-muted">
        <div className="h-full rounded-full bg-chart-5" style={{ width: `${Math.min(100, ratio * 100)}%` }} />
      </div>
      <span className="tabular w-12 text-right">{fmtPercent(ratio)}</span>
    </div>
  )
}
