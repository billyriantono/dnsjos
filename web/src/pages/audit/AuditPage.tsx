import { useInfiniteQuery } from '@tanstack/react-query'
import { Fragment, useState } from 'react'
import { LuChevronDown, LuChevronRight, LuScrollText } from 'react-icons/lu'

import { AdminOnly } from '@/components/AdminOnly'
import { EmptyState } from '@/components/EmptyState'
import { PageHeader } from '@/components/PageHeader'
import { TimeAgo } from '@/components/TimeAgo'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { api } from '@/lib/api/client'
import type { AuditEntry } from '@/lib/api/types'

const PAGE = 50

const hasDetails = (d: unknown) => d != null && !(typeof d === 'object' && Object.keys(d).length === 0)

export default function AuditPage() {
  return (
    <AdminOnly title="Audit log">
      <Audit />
    </AdminOnly>
  )
}

function Audit() {
  const q = useInfiniteQuery({
    queryKey: ['audit', 'infinite'],
    queryFn: ({ pageParam }) => api.audit.list({ limit: PAGE, before: pageParam }),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last) => (last.items.length < PAGE ? undefined : last.items[last.items.length - 1].id),
  })
  const rows = q.data?.pages.flatMap((p) => p.items) ?? []
  const [open, setOpen] = useState<Set<number>>(new Set())
  const toggle = (id: number) =>
    setOpen((s) => {
      const n = new Set(s)
      if (!n.delete(id)) n.add(id)
      return n
    })

  return (
    <>
      <PageHeader title="Audit log" description="Every change made through the panel, newest first." />
      <div className="overflow-hidden rounded-lg border bg-card">
        <Table>
          <TableHeader className="bg-muted/40">
            <TableRow className="hover:bg-transparent">
              <TableHead className="h-9 w-8">
                <span className="sr-only">Details</span>
              </TableHead>
              <TableHead className="h-9 text-xs">When</TableHead>
              <TableHead className="h-9 text-xs">User</TableHead>
              <TableHead className="h-9 text-xs">Action</TableHead>
              <TableHead className="h-9 text-xs">Target</TableHead>
              <TableHead className="h-9 text-xs">IP</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {q.isPending
              ? Array.from({ length: 10 }, (_, i) => (
                  <TableRow key={i} className="hover:bg-transparent">
                    {Array.from({ length: 6 }, (_, j) => (
                      <TableCell key={j}>
                        <Skeleton className="h-4 w-full max-w-32" />
                      </TableCell>
                    ))}
                  </TableRow>
                ))
              : rows.map((e) => <AuditRow key={e.id} entry={e} open={open.has(e.id)} onToggle={() => toggle(e.id)} />)}
            {!q.isPending && rows.length === 0 && (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={6} className="p-0">
                  {q.error ? (
                    <EmptyState title="Could not load the audit log" description={q.error.message} />
                  ) : (
                    <EmptyState icon={LuScrollText} title="No audit entries yet" />
                  )}
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
      {q.hasNextPage && (
        <div className="flex justify-center">
          <Button variant="outline" onClick={() => q.fetchNextPage()} disabled={q.isFetchingNextPage}>
            {q.isFetchingNextPage ? 'Loading…' : 'Load older entries'}
          </Button>
        </div>
      )}
      {!q.hasNextPage && rows.length > 0 && <p className="text-center text-xs text-muted-foreground">Beginning of the log.</p>}
    </>
  )
}

function AuditRow({ entry: e, open, onToggle }: { entry: AuditEntry; open: boolean; onToggle: () => void }) {
  const details = hasDetails(e.details)
  const Chevron = open ? LuChevronDown : LuChevronRight
  return (
    <Fragment>
      <TableRow onClick={details ? onToggle : undefined} className={details ? 'cursor-pointer' : undefined}>
        <TableCell className="w-8 pr-0 text-muted-foreground">
          {details && (
            <button
              type="button"
              aria-expanded={open}
              aria-label={`${open ? 'Hide' : 'Show'} details`}
              className="flex rounded-sm outline-none focus-visible:ring-2 focus-visible:ring-ring"
              onClick={(ev) => {
                ev.stopPropagation()
                onToggle()
              }}
            >
              <Chevron className="size-4" />
            </button>
          )}
        </TableCell>
        <TableCell className="whitespace-nowrap">
          <TimeAgo date={e.at} />
        </TableCell>
        <TableCell>{e.user_email || <span className="text-muted-foreground">system</span>}</TableCell>
        <TableCell>
          <Badge variant="outline" className="font-mono">
            {e.action}
          </Badge>
        </TableCell>
        <TableCell className="max-w-72">
          <span className="text-muted-foreground">{e.target_type}</span>
          {e.target_id && (
            <code className="ml-1.5 block truncate font-mono text-xs sm:inline" title={e.target_id}>
              {e.target_id}
            </code>
          )}
        </TableCell>
        <TableCell className="font-mono text-xs">{e.ip || '—'}</TableCell>
      </TableRow>
      {open && (
        <TableRow className="bg-muted/30 hover:bg-muted/30">
          <TableCell />
          <TableCell colSpan={5}>
            <pre tabIndex={0} className="max-h-80 overflow-auto rounded-md bg-background p-3 font-mono text-xs whitespace-pre-wrap">
              {JSON.stringify(e.details, null, 2)}
            </pre>
          </TableCell>
        </TableRow>
      )}
    </Fragment>
  )
}
