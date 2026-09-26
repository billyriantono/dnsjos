import { useMemo } from 'react'
import { LuActivity, LuCalendarDays, LuChartNoAxesColumn, LuCircleX, LuDownload, LuGlobe, LuSearchX } from 'react-icons/lu'
import { useSearchParams } from 'react-router'
import { Bar, BarChart, CartesianGrid, XAxis, YAxis } from 'recharts'

import { ApproxMark, ShareBar } from '@/components/analytics/shared'
import { ymd } from '@/components/analytics/ymd'
import { CopyButton } from '@/components/CopyButton'
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
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { api, useAnalytics } from '@/lib/api/client'
import type { AnalyticsKind, AnalyticsTopEntry } from '@/lib/api/types'
import { fmtCompact, fmtNumber, fmtPercent } from '@/lib/format'

const PRESETS = {
  today: { label: 'Today', range: (n: Date) => [n, n] },
  '7d': { label: 'Last 7 days', range: (n: Date) => [new Date(n.getFullYear(), n.getMonth(), n.getDate() - 6), n] },
  '30d': { label: 'Last 30 days', range: (n: Date) => [new Date(n.getFullYear(), n.getMonth(), n.getDate() - 29), n] },
  month: { label: 'This month', range: (n: Date) => [new Date(n.getFullYear(), n.getMonth(), 1), n] },
  year: { label: 'This year', range: (n: Date) => [new Date(n.getFullYear(), 0, 1), n] },
} satisfies Record<string, { label: string; range: (n: Date) => Date[] }>
type Preset = keyof typeof PRESETS | 'custom'

type View = 'queried' | 'nxdomain' | 'servfail'
const VIEWS: Record<View, { label: string; what: string; empty: string }> = {
  queried: { label: 'Top domains', what: 'Queries', empty: 'No queries recorded' },
  nxdomain: { label: 'NXDOMAIN', what: 'NXDOMAIN answers', empty: 'No NXDOMAIN answers' },
  servfail: { label: 'SERVFAIL', what: 'SERVFAIL answers', empty: 'No SERVFAIL answers' },
}

const dayLabel = (d: string) => new Date(`${d}T00:00:00`).toLocaleDateString(undefined, { day: 'numeric', month: 'short' })
const volumeConfig = { total: { label: 'Queries', color: 'var(--chart-1)' } } satisfies ChartConfig

export default function AnalyticsPage() {
  // All filters live in the URL so views can be linked (e.g. from a node's detail page).
  const [params, setParams] = useSearchParams()
  const set = (p: Record<string, string | undefined>) =>
    setParams(
      (cur) => {
        for (const [k, v] of Object.entries(p)) {
          if (v) cur.set(k, v)
          else cur.delete(k)
        }
        return cur
      },
      { replace: true },
    )
  const preset = (params.get('range') ?? '7d') as Preset
  const k = params.get('kind')
  const view: View = k === 'nxdomain' || k === 'servfail' ? k : 'queried'
  const grouped = params.get('grouped') === '1'
  const nodeId = params.get('node') ?? ''
  const limit = Number(params.get('limit')) || 100

  const { from, to } = useMemo(() => {
    if (preset in PRESETS) {
      const [f, t] = PRESETS[preset as keyof typeof PRESETS].range(new Date())
      return { from: ymd(f), to: ymd(t) }
    }
    return { from: params.get('from') ?? '', to: params.get('to') ?? '' }
  }, [preset, params])
  const kind: AnalyticsKind = view === 'queried' && grouped ? 'queried_grouped' : view
  const valid = from !== '' && to !== '' && from <= to
  const q = { from, to, node_id: nodeId || undefined, kind, limit }
  const { data, isPending, isFetching, error } = useAnalytics(q)
  const loading = !valid || isPending

  const total = data?.total ?? 0
  const nx = data?.by_rcode.NXDOMAIN ?? 0
  const sf = data?.by_rcode.SERVFAIL ?? 0
  const days = data?.by_day.length || 1
  const approx = data?.top.some((t) => t.approximate)

  const columns: Column<AnalyticsTopEntry>[] = [
    { key: 'rank', header: '#', sortValue: (r) => r.rank, cell: (r) => <span className="text-muted-foreground">{r.rank}</span> },
    {
      key: 'name',
      header: grouped && view === 'queried' ? 'Registered domain' : 'Name',
      sortValue: (r) => r.name,
      cell: (r) => (
        <div className="group flex items-center gap-2">
          <code className="font-mono text-xs break-all">{r.name}</code>
          <CopyButton value={r.name} className="size-6 shrink-0 opacity-60 group-hover:opacity-100 [&_svg]:size-3" />
        </div>
      ),
    },
    {
      key: 'count',
      header: VIEWS[view].what,
      align: 'right',
      sortValue: (r) => r.count,
      cell: (r) => (
        <span className="tabular inline-flex items-center gap-1">
          {r.approximate && <ApproxMark />}
          {fmtNumber(r.count)}
        </span>
      ),
    },
    { key: 'share', header: 'Share', align: 'right', className: 'hidden sm:table-cell', sortValue: (r) => r.share, cell: (r) => <ShareBar ratio={r.share} /> },
  ]

  return (
    <>
      <PageHeader
        title="Analytics"
        description="Most-queried domains, failing names, and query mix across the fleet. No client addresses are collected."
        actions={
          <Button variant="outline" size="sm" asChild disabled={!valid}>
            <a href={valid ? api.analytics.csvUrl(q) : undefined} download>
              <LuDownload />
              Export CSV
            </a>
          </Button>
        }
      />

      <Card className="py-4">
        <CardContent className="flex flex-wrap items-end gap-3 px-4">
          <div className="grid gap-1.5">
            <span className="text-xs text-muted-foreground">Period</span>
            <Select value={preset} onValueChange={(v) => set(v === 'custom' ? { range: v, from, to } : { range: v, from: undefined, to: undefined })}>
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
            <Input type="date" className="w-40" value={from} max={to} onChange={(e) => set({ range: 'custom', from: e.target.value, to })} />
          </label>
          <label className="grid gap-1.5">
            <span className="text-xs text-muted-foreground">To</span>
            <Input type="date" className="w-40" value={to} min={from} onChange={(e) => set({ range: 'custom', from, to: e.target.value })} />
          </label>
          <div className="grid gap-1.5">
            <span className="text-xs text-muted-foreground">Node</span>
            <NodeSelect value={nodeId} onChange={(id) => set({ node: id || undefined })} />
          </div>
          {!valid && <p className="text-sm text-destructive">“From” must be on or before “To”.</p>}
          {error && <p className="text-sm text-destructive">{error.message}</p>}
          {isFetching && !isPending && <span className="text-xs text-muted-foreground">Updating…</span>}
        </CardContent>
      </Card>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard title="Queries" icon={LuActivity} value={fmtNumber(total)} hint={`${from} → ${to}`} loading={loading} />
        <StatCard title="Daily average" icon={LuCalendarDays} value={fmtCompact(total / days)} hint={`${days} days`} loading={loading} />
        <StatCard title="NXDOMAIN" icon={LuSearchX} value={fmtPercent(total ? nx / total : 0)} hint={`${fmtCompact(nx)} answers`} loading={loading} />
        <StatCard title="SERVFAIL" icon={LuCircleX} value={fmtPercent(total ? sf / total : 0, 2)} hint={`${fmtCompact(sf)} answers`} loading={loading} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Daily volume</CardTitle>
          <CardDescription>Answered queries per day, {nodeId ? 'selected node' : 'all nodes'}.</CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <Skeleton className="h-56 w-full" />
          ) : total === 0 ? (
            <EmptyState
              icon={LuChartNoAxesColumn}
              title="No queries recorded in this period"
              description="Nodes report analytics every minute when it is enabled in their profile."
              className="h-56"
            />
          ) : (
            <ChartContainer config={volumeConfig} className="aspect-auto h-56 w-full">
              <BarChart data={data?.by_day} margin={{ left: 4, right: 4 }}>
                <CartesianGrid vertical={false} />
                <XAxis dataKey="day" tickLine={false} axisLine={false} tickFormatter={dayLabel} minTickGap={16} />
                <YAxis tickLine={false} axisLine={false} width={48} tickFormatter={(v: number) => fmtCompact(v)} />
                <ChartTooltip
                  content={
                    <ChartTooltipContent
                      labelFormatter={(v) => dayLabel(String(v))}
                      formatter={(v) => <span className="tabular font-medium">{fmtNumber(Number(v))} queries</span>}
                    />
                  }
                />
                <Bar dataKey="total" fill="var(--color-total)" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ChartContainer>
          )}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card className="min-w-0 xl:col-span-2">
          <CardHeader className="gap-3">
            <Tabs value={view} onValueChange={(v) => set({ kind: v === 'queried' ? undefined : v })}>
              <div className="flex flex-wrap items-center gap-2">
                <TabsList aria-label="List">
                  {Object.entries(VIEWS).map(([k, v]) => (
                    <TabsTrigger key={k} value={k} className="px-3">
                      {v.label}
                    </TabsTrigger>
                  ))}
                </TabsList>
                {view === 'queried' && (
                  <Tabs value={grouped ? 'grouped' : 'raw'} onValueChange={(v) => set({ grouped: v === 'grouped' ? '1' : undefined })}>
                    <TabsList aria-label="Grouping" className="h-8">
                      <TabsTrigger value="raw" className="px-2.5 text-xs">
                        Raw
                      </TabsTrigger>
                      <TabsTrigger value="grouped" className="px-2.5 text-xs">
                        Grouped
                      </TabsTrigger>
                    </TabsList>
                  </Tabs>
                )}
                <Select value={String(limit)} onValueChange={(v) => set({ limit: v === '100' ? undefined : v })}>
                  <SelectTrigger size="sm" className="ml-auto w-28" aria-label="Rows">
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
            </Tabs>
            <CardDescription>
              {view === 'queried'
                ? grouped
                  ? 'Grouped by registered domain (www.example.com and api.example.com count as example.com).'
                  : 'Exact query names.'
                : `Names answered with ${view.toUpperCase()}; share is of all ${view.toUpperCase()} answers.`}
              {approx && (
                <>
                  {' '}
                  <ApproxMark /> marks approximate counts.
                </>
              )}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={columns}
              rows={valid ? data?.top : undefined}
              loading={loading}
              error={error}
              rowKey={(r) => r.name}
              defaultSort={{ key: 'rank' }}
              skeletonRows={10}
              empty={<EmptyState icon={LuGlobe} title={VIEWS[view].empty} />}
            />
          </CardContent>
        </Card>
        <div className="grid content-start gap-4">
          <Breakdown title="Query types" data={data?.by_qtype} total={total} loading={loading} />
          <Breakdown title="Response codes" data={data?.by_rcode} total={total} loading={loading} />
        </div>
      </div>
    </>
  )
}

function Breakdown({ title, data, total, loading }: { title: string; data?: Record<string, number>; total: number; loading: boolean }) {
  const rows = Object.entries(data ?? {})
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1])
  const top = rows.slice(0, 10)
  const rest = rows.slice(10).reduce((s, [, n]) => s + n, 0)
  if (rest) top.push(['other', rest])
  return (
    <Card className="gap-3">
      <CardHeader>
        <CardTitle className="text-sm">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        {loading ? (
          <Skeleton className="h-40 w-full" />
        ) : top.length === 0 ? (
          <p className="py-6 text-center text-sm text-muted-foreground">No data</p>
        ) : (
          <ul className="grid gap-2 text-sm">
            {top.map(([name, n]) => (
              <li key={name} className="grid grid-cols-[5.5rem_1fr_auto] items-center gap-2">
                <span className="truncate font-mono text-xs">{name}</span>
                <div className="h-2 overflow-hidden rounded-full bg-muted">
                  <div className="h-full rounded-full bg-chart-2" style={{ width: `${total ? (n / total) * 100 : 0}%` }} />
                </div>
                <span className="tabular w-24 text-right text-xs text-muted-foreground">
                  {fmtCompact(n)} · {fmtPercent(total ? n / total : 0)}
                </span>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}
