import { LuNetwork } from 'react-icons/lu'

import { EmptyState } from '@/components/EmptyState'
import { TimeAgo } from '@/components/TimeAgo'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useNodeDualStack } from '@/lib/api/client'
import type { DualStackName } from '@/lib/api/types'

const speed = (v: number) => (v < 0 ? 'no answer' : `${v.toFixed(1)} ms`)

/** SPEC §6.8: names whose A or AAAA answers this node drops (smartdns dualstack-ip-selection). */
export function NodeDualStackTab({ id }: { id: string }) {
  const q = useNodeDualStack(id)
  const d = q.data
  const items: DualStackName[] = d?.names ?? []
  const reported = d && !d.at.startsWith('0001-')
  return (
    <Card className="gap-3 py-4">
      <CardHeader className="px-4">
        <CardTitle className="flex items-center gap-2 text-sm">
          Dual-stack selection ({items.length})
          {reported && !d.ipv6 && (
            <Badge variant="outline" className="border-warning/40 text-warning">
              no IPv6 on node
            </Badge>
          )}
        </CardTitle>
        <CardDescription className="text-xs">
          Every 10 minutes the agent speed-checks the busiest names with AAAA answers over IPv4 and IPv6, like smartdns. The
          slower family of a listed name is answered NODATA so clients use the faster one. Listed names are re-measured hourly,
          others every 6 hours.
          {reported && (
            <>
              {' '}
              {d.checked} names measured, last report <TimeAgo date={d.at} />.
            </>
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="px-4">
        {q.isPending ? (
          <Skeleton className="h-24" />
        ) : !items.length ? (
          <EmptyState
            icon={LuNetwork}
            title={reported ? 'No answers dropped' : 'No report yet'}
            description={
              !reported
                ? 'Enable dual-stack selection in the profile (or a node override); the agent reports within 10 minutes.'
                : d.ipv6
                  ? 'Every measured name is about as fast over IPv6 as over IPv4.'
                  : 'This node has no IPv6 route, so it cannot measure IPv6 and drops nothing.'
            }
          />
        ) : (
          <div className="overflow-x-auto rounded-md border">
            <table className="w-full text-sm">
              <thead className="bg-muted/50 text-xs text-muted-foreground">
                <tr>
                  <th className="px-3 py-2 text-left font-medium">Name</th>
                  <th className="px-3 py-2 text-left font-medium">Answers</th>
                  <th className="px-3 py-2 text-right font-medium">IPv4</th>
                  <th className="px-3 py-2 text-right font-medium">IPv6</th>
                  <th className="px-3 py-2 text-right font-medium">TTL</th>
                  <th className="px-3 py-2 text-right font-medium">Hits</th>
                  <th className="px-3 py-2 text-right font-medium">Checked</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {items.map((e) => (
                  <tr key={e.name}>
                    <td className="px-3 py-2 font-mono text-xs">{e.name}</td>
                    <td className="px-3 py-2 text-xs">
                      <Badge variant="outline" className="font-normal">
                        {e.prefer === 'ipv4' ? 'IPv4 only (AAAA dropped)' : 'IPv6 only (A dropped)'}
                      </Badge>
                    </td>
                    <td className="px-3 py-2 text-right text-xs tabular-nums">{speed(e.v4_ms)}</td>
                    <td className="px-3 py-2 text-right text-xs tabular-nums">{speed(e.v6_ms)}</td>
                    <td className="px-3 py-2 text-right text-xs tabular-nums">{e.ttl}s</td>
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
