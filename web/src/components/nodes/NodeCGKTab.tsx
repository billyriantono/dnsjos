import { LuCloud, LuRefreshCw, LuShieldOff } from 'react-icons/lu'
import { toast } from 'sonner'

import { RequireAdmin } from '@/app/auth'
import { EmptyState } from '@/components/EmptyState'
import { StatusBadge } from '@/components/StatusBadge'
import { TimeAgo } from '@/components/TimeAgo'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useNodeCGK, useNodeCGKLearned, useNodeCommand } from '@/lib/api/client'
import type { CGKIPv6, CGKLearned, NodeLive } from '@/lib/api/types'

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
  const r = d && { ...d, aliases: d.aliases ?? [], aliases6: d.aliases6 ?? [], rewrite_ranges: d.rewrite_ranges ?? [], pools: d.pools ?? [] }

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
          <CardDescription className="text-xs">
            Rewrites Cloudflare answers from ranges this node reaches outside CGK to aliases measured to be served from CGK (Jakarta).
          </CardDescription>
          <CardAction>
            <RequireAdmin>
              <Button size="sm" variant="outline" onClick={refresh} disabled={cmd.isPending}>
                <LuRefreshCw className={cmd.isPending ? 'animate-spin' : undefined} /> Refresh now
              </Button>
            </RequireAdmin>
          </CardAction>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-3 px-4 text-sm sm:grid-cols-4">
          <Fact label="Aliases active" value={st ? `${st.aliases}${st.aliases6 ? ` + ${st.aliases6} IPv6` : ''}` : '—'} />
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
              <CardTitle className="flex items-center gap-2 text-sm">
                IPv6 aliases ({r.aliases6.length}) <IPv6Badge status={r.ipv6} />
              </CardTitle>
              <CardDescription className="text-xs">{IPV6_TEXT[r.ipv6 || '']}</CardDescription>
            </CardHeader>
            <CardContent className="px-4">
              <Chips items={r.aliases6} empty="AAAA answers are not rewritten on this node." />
            </CardContent>
          </Card>
          <Card className="gap-3 py-4">
            <CardHeader className="px-4">
              <CardTitle className="text-sm">Rewrite ranges ({r.rewrite_ranges.length})</CardTitle>
              <CardDescription className="text-xs">Pools served outside CGK from this node: their answers are rewritten.</CardDescription>
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

      <LearnedExclusions id={id} />
    </div>
  )
}

const IPV6_TEXT: Record<CGKIPv6, string> = {
  ok: 'AAAA answers in Cloudflare IPv6 ranges served outside CGK are rewritten to these addresses.',
  no_connectivity: 'This node has no IPv6 connectivity, so it cannot measure Cloudflare over IPv6. AAAA answers keep their real addresses until the node gets IPv6.',
  too_few_aliases: 'Too few IPv6 addresses were served from CGK and answered like the real sites; AAAA answers are not rewritten.',
  not_configured: 'The profile has no IPv6 rewrite or alias pools.',
  '': 'This agent predates IPv6 CGK support.',
}

function IPv6Badge({ status }: { status: CGKIPv6 }) {
  if (status === 'ok') return <Badge className="bg-success/15 text-success">IPv6 on</Badge>
  if (status === 'no_connectivity') return <Badge variant="outline" className="border-warning/40 text-warning">no IPv6 on node</Badge>
  return <Badge variant="outline">IPv6 off</Badge>
}

const code = (c: string) => (c === '000' ? 'no HTTPS' : c)

/** SPEC §6.6: names the agent found broken through an alias; they are never rewritten. */
function LearnedExclusions({ id }: { id: string }) {
  const q = useNodeCGKLearned(id)
  const d = q.data
  const items: CGKLearned[] = d?.excluded ?? []
  const reported = d && !d.at.startsWith('0001-')
  return (
    <Card className="gap-3 py-4">
      <CardHeader className="px-4">
        <CardTitle className="text-sm">Learned exclusions ({items.length})</CardTitle>
        <CardDescription className="text-xs">
          Every 10 minutes the agent opens the busiest rewritten names through their real IP and through the CGK alias. A name
          whose real IP does not serve HTTPS (Spectrum and other non-web apps) or that answers differently through the alias is
          no longer rewritten. Re-checked weekly.
          {reported && (
            <>
              {' '}
              {d.checked} names checked, last report <TimeAgo date={d.at} />.
            </>
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="px-4">
        {q.isPending ? (
          <Skeleton className="h-24" />
        ) : !items.length ? (
          <EmptyState
            icon={LuShieldOff}
            title={reported ? 'Nothing excluded' : 'No report yet'}
            description={reported ? 'Every checked name works through its CGK alias.' : 'The agent reports after its first check (within 10 minutes).'}
          />
        ) : (
          <div className="overflow-x-auto rounded-md border">
            <table className="w-full text-sm">
              <thead className="bg-muted/50 text-xs text-muted-foreground">
                <tr>
                  <th className="px-3 py-2 text-left font-medium">Name</th>
                  <th className="px-3 py-2 text-left font-medium">Real IP → alias</th>
                  <th className="px-3 py-2 text-left font-medium">HTTP real / alias</th>
                  <th className="px-3 py-2 text-right font-medium">Hits</th>
                  <th className="px-3 py-2 text-right font-medium">Checked</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {items.map((e) => (
                  <tr key={e.name}>
                    <td className="px-3 py-2 font-mono text-xs">{e.name}</td>
                    <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
                      {e.real_ip} → {e.alias_ip}
                    </td>
                    <td className="px-3 py-2 text-xs">
                      <Badge variant="outline" className="font-mono font-normal">
                        {code(e.real_code)}
                      </Badge>{' '}
                      /{' '}
                      <Badge variant="outline" className="font-mono font-normal">
                        {code(e.alias_code)}
                      </Badge>
                    </td>
                    <td className="px-3 py-2 text-right tabular-nums">{e.hits.toLocaleString()}</td>
                    <td className="px-3 py-2 text-right text-xs text-muted-foreground">
                      <TimeAgo date={e.checked_at} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
