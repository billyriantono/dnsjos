import { Link } from 'react-router'
import { LuActivity, LuDatabaseZap, LuServer, LuShieldAlert, LuShieldBan, LuListChecks } from 'react-icons/lu'

import { PageHeader } from '@/components/PageHeader'
import { StatCard } from '@/components/StatCard'
import { MetricChart } from '@/components/nodes/MetricChart'
import { toRows } from '@/components/nodes/metrics'
import { NodesTable } from '@/components/nodes/NodesTable'
import { Button } from '@/components/ui/button'
import { useFleetMetrics, useNodes, useOverview } from '@/lib/api/client'
import { fmtAgo, fmtCompact, fmtNumber, fmtPercent, fmtQps, shortSha } from '@/lib/format'

export default function OverviewPage() {
  const ov = useOverview()
  const metrics = useFleetMetrics()
  const nodes = useNodes()
  const o = ov.data
  const rows = toRows(metrics.data)
  const build = o?.current_build
  const loading = ov.isPending

  return (
    <>
      <PageHeader title="Overview" description="Fleet health at a glance." />
      {ov.error && <p className="text-sm text-destructive">Could not load the overview: {ov.error.message}</p>}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <StatCard
          title="Nodes online"
          icon={LuServer}
          loading={loading}
          value={`${o?.nodes.online ?? 0} / ${o?.nodes_total ?? 0}`}
          hint={o && [o.nodes.degraded && `${o.nodes.degraded} degraded`, o.nodes.offline && `${o.nodes.offline} offline`].filter(Boolean).join(' · ')}
        />
        <StatCard title="Fleet QPS" icon={LuActivity} loading={loading} value={fmtQps(o?.qps)} />
        <StatCard title="Cache hit" icon={LuDatabaseZap} loading={loading} value={fmtPercent(o?.cache_hit_ratio)} />
        <StatCard title="Blocked 24 h" icon={LuShieldBan} loading={loading} value={fmtCompact(o?.blocked_24h)} hint={`${fmtNumber(o?.blocked_24h)} queries`} />
        <StatCard title="Offenders" icon={LuShieldAlert} loading={loading} value={fmtNumber(o?.active_offenders)} hint={<Link to="/offenders" className="hover:underline">View offenders</Link>} />
        <StatCard
          title="Blocklist"
          icon={LuListChecks}
          loading={loading}
          value={build ? fmtAgo(build.finished_at ?? build.started_at) : 'none'}
          hint={build ? `${fmtCompact(build.domains)} domains · ${shortSha(build.sha256)}` : 'No build published yet'}
        />
      </div>
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <MetricChart title="Fleet queries per second" description="All nodes, last 6 hours" rows={rows} loading={metrics.isPending} series={[{ key: 'qps', label: 'QPS', color: 'var(--chart-1)' }]} />
        <MetricChart
          title="Cache hit ratio"
          description="All nodes, last 6 hours"
          kind="line"
          unit="%"
          domain={[0, 100]}
          rows={rows}
          loading={metrics.isPending}
          series={[{ key: 'hit', label: 'Cache hit %', color: 'var(--chart-2)' }]}
        />
      </div>
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-medium">Nodes</h2>
          <Button asChild variant="ghost" size="sm">
            <Link to="/nodes">All nodes</Link>
          </Button>
        </div>
        <NodesTable rows={nodes.data?.items} loading={nodes.isPending} error={nodes.error} compact />
      </div>
    </>
  )
}
