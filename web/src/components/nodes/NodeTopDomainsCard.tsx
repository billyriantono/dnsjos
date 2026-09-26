import { LuArrowRight } from 'react-icons/lu'
import { Link } from 'react-router'

import { ApproxMark, ShareBar } from '@/components/analytics/shared'
import { ymd } from '@/components/analytics/ymd'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useAnalytics } from '@/lib/api/client'
import { fmtCompact } from '@/lib/format'

/** Compact top-10 registered domains of today for one node (SPEC §19). */
export function NodeTopDomainsCard({ id }: { id: string }) {
  const today = ymd(new Date())
  const { data, isPending, error } = useAnalytics({ from: today, to: today, node_id: id, kind: 'queried_grouped', limit: 10 })
  return (
    <Card className="gap-2 py-4">
      <CardHeader className="px-4">
        <CardTitle className="text-sm">Top domains today</CardTitle>
        <CardAction>
          <Button asChild variant="ghost" size="sm" className="h-7">
            <Link to={`/analytics?node=${encodeURIComponent(id)}&range=today&grouped=1`}>
              Analytics <LuArrowRight />
            </Link>
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent className="px-4 text-sm">
        {isPending ? (
          <Skeleton className="h-40 w-full" />
        ) : error ? (
          <p className="text-destructive">{error.message}</p>
        ) : !data.top.length ? (
          <p className="py-4 text-center text-muted-foreground">No queries recorded today.</p>
        ) : (
          <ol className="grid gap-1.5">
            {data.top.map((t) => (
              <li key={t.name} className="grid grid-cols-[1.5rem_1fr_auto_auto] items-center gap-2">
                <span className="text-xs text-muted-foreground">{t.rank}</span>
                <code className="truncate font-mono text-xs">{t.name}</code>
                <span className="tabular text-xs">
                  {t.approximate && <ApproxMark />} {fmtCompact(t.count)}
                </span>
                <ShareBar ratio={t.share} className="w-12" />
              </li>
            ))}
          </ol>
        )}
      </CardContent>
    </Card>
  )
}
