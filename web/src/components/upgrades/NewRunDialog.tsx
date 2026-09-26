import { useState } from 'react'
import { LuArrowDown, LuArrowUp, LuCircleAlert, LuCircleCheck, LuGripVertical, LuInfo, LuListRestart, LuPlay } from 'react-icons/lu'
import { toast } from 'sonner'

import { StatusBadge } from '@/components/StatusBadge'
import { Field } from '@/components/ops/Field'
import { toastError } from '@/components/ops/toast'
import { fmtSeries, sortVersions } from '@/components/upgrades/versions'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { useCreateUpgrade, useMeta, useNodes } from '@/lib/api/client'
import type { Node, UpgradeKind } from '@/lib/api/types'
import { fmtQps } from '@/lib/format'
import { cn } from '@/lib/utils'

type Check = { level: 'block' | 'warn' | 'ok'; text: string }

const leastBusy = (nodes: Node[]) => [...nodes].sort((a, b) => a.qps - b.qps).map((n) => n.id)

const checkIcon = {
  block: <LuCircleAlert className="size-4 shrink-0 text-destructive" />,
  warn: <LuInfo className="size-4 shrink-0 text-warning" />,
  ok: <LuCircleCheck className="size-4 shrink-0 text-success" />,
}

/** Start a rolling run: pick kind, nodes + order, and a version every chosen node can install. */
export function NewRunDialog({ activeRun, onCreated }: { activeRun: boolean; onCreated: (id: number) => void }) {
  const nodes = useNodes()
  const meta = useMeta()
  const create = useCreateUpgrade()
  const [open, setOpen] = useState(false)
  const [kind, setKind] = useState<UpgradeKind>('dnsdist')
  const [order, setOrder] = useState<string[]>([])
  const [skip, setSkip] = useState<Set<string>>(new Set())
  const [pick, setPick] = useState<string>()
  const [drag, setDrag] = useState<string>()

  const all = nodes.data?.items ?? []
  const byId = new Map(all.map((n) => [n.id, n]))
  // Nodes enrolled while the dialog is open are appended rather than dropped.
  const ordered = [...order.filter((id) => byId.has(id)), ...leastBusy(all).filter((id) => !order.includes(id))].map((id) => byId.get(id)!)
  const chosen = ordered.filter((n) => !skip.has(n.id))

  const common = sortVersions(
    chosen.length ? chosen.map((n) => n.dnsdist_available ?? []).reduce((acc, vs) => acc.filter((v) => vs.includes(v))) : [],
  )
  const target = kind === 'agent' ? (meta.data?.agent_version ?? '') : pick && common.includes(pick) ? pick : (common[0] ?? '')

  const checks: Check[] = []
  if (activeRun) checks.push({ level: 'block', text: 'Another run is active: finish or abort it first.' })
  if (!chosen.length) checks.push({ level: 'block', text: 'Select at least one node.' })
  for (const n of chosen) if (n.status !== 'online') checks.push({ level: 'block', text: `${n.name} is ${n.status}.` })
  if (kind === 'dnsdist') {
    for (const n of chosen)
      if (!n.dnsdist_available?.length) checks.push({ level: 'block', text: `${n.name} has no version inventory yet (use Check for updates on the node).` })
    if (chosen.length && !common.length) checks.push({ level: 'block', text: 'No version is available on every selected node (different series?).' })
    const series = new Set(chosen.map((n) => n.dnsdist_repo_series))
    if (series.size > 1) checks.push({ level: 'warn', text: `Selected nodes follow different series: ${[...series].map(fmtSeries).join(', ')}.` })
    for (const n of chosen) if (target && n.dnsdist_version === target) checks.push({ level: 'warn', text: `${n.name} already runs ${target}.` })
  } else {
    for (const n of chosen) if (!n.agent_outdated) checks.push({ level: 'warn', text: `${n.name} already runs the panel's agent version.` })
  }
  if (chosen.length && chosen.length === all.length && all.length < 2 && kind === 'dnsdist')
    checks.push({ level: 'warn', text: 'Only one node: its clients see a short outage while dnsdist restarts.' })
  const blocked = checks.some((c) => c.level === 'block') || (kind === 'dnsdist' && !target)
  if (!blocked) checks.push({ level: 'ok', text: `${chosen.length} node(s), one at a time; each must be healthy again before the next starts.` })

  const move = (id: string, to: number) => {
    const ids = ordered.map((n) => n.id).filter((x) => x !== id)
    ids.splice(Math.max(0, Math.min(to, ids.length)), 0, id)
    setOrder(ids)
  }

  const reset = (o: boolean) => {
    setOpen(o)
    if (o) {
      setOrder(leastBusy(all))
      setSkip(new Set())
      setPick(undefined)
    }
  }

  const start = () =>
    create.mutateAsync({ kind, target_version: kind === 'agent' ? '' : target, node_ids: chosen.map((n) => n.id) }).then((run) => {
      toast.success(`Run #${run.id} started`)
      setOpen(false)
      onCreated(run.id)
    }, toastError)

  return (
    <Dialog open={open} onOpenChange={reset}>
      <DialogTrigger asChild>
        <Button>
          <LuPlay /> New rolling upgrade
        </Button>
      </DialogTrigger>
      <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>New rolling upgrade</DialogTitle>
          <DialogDescription>
            Nodes are upgraded one at a time in this order. A failed node pauses the run (dnsdist upgrades roll back on that node automatically).
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4 sm:grid-cols-2">
          <Field id="run-kind" label="Upgrade">
            <Select value={kind} onValueChange={(v) => setKind(v as UpgradeKind)}>
              <SelectTrigger id="run-kind" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="dnsdist">dnsdist</SelectItem>
                <SelectItem value="agent">Agent</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          <Field id="run-target" label="Target version" hint={kind === 'dnsdist' ? 'Versions available on all selected nodes.' : "The agent version this panel ships."}>
            {kind === 'dnsdist' ? (
              <Select value={target} onValueChange={setPick} disabled={!common.length}>
                <SelectTrigger id="run-target" className="w-full font-mono text-xs">
                  <SelectValue placeholder="No common version" />
                </SelectTrigger>
                <SelectContent>
                  {common.map((v) => (
                    <SelectItem key={v} value={v} className="font-mono text-xs">
                      {v}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            ) : (
              <div id="run-target" className="flex h-9 items-center rounded-md border bg-muted/50 px-3 font-mono text-xs">
                {target || '—'}
              </div>
            )}
          </Field>
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between gap-2">
            <p className="text-sm font-medium">Order</p>
            <Button type="button" variant="ghost" size="sm" onClick={() => setOrder(leastBusy(all))}>
              <LuListRestart /> Least busy first
            </Button>
          </div>
          <ol className="divide-y rounded-md border">
            {ordered.map((n, i) => (
              <li
                key={n.id}
                draggable
                onDragStart={() => setDrag(n.id)}
                onDragEnd={() => setDrag(undefined)}
                onDragOver={(e) => e.preventDefault()}
                onDrop={() => drag && drag !== n.id && move(drag, i)}
                className={cn('flex items-center gap-2 px-2 py-1.5 text-sm', drag === n.id && 'opacity-50', skip.has(n.id) && 'text-muted-foreground')}
              >
                <LuGripVertical className="size-4 shrink-0 cursor-grab text-muted-foreground" />
                <Checkbox
                  checked={!skip.has(n.id)}
                  aria-label={`Include ${n.name}`}
                  onCheckedChange={(c) =>
                    setSkip((s) => {
                      const next = new Set(s)
                      if (c) next.delete(n.id)
                      else next.add(n.id)
                      return next
                    })
                  }
                />
                <span className="tabular w-5 text-right text-xs text-muted-foreground">{i + 1}.</span>
                <span className="min-w-0 flex-1 truncate font-medium">{n.name}</span>
                <StatusBadge status={n.status} />
                <span className="hidden w-40 truncate text-right font-mono text-xs text-muted-foreground sm:inline">
                  {kind === 'dnsdist' ? n.dnsdist_version || '—' : n.agent_version || '—'}
                </span>
                <span className="tabular hidden w-20 text-right text-xs text-muted-foreground sm:inline">{fmtQps(n.qps)}</span>
                <Button type="button" variant="ghost" size="icon" className="size-7" disabled={i === 0} onClick={() => move(n.id, i - 1)} aria-label={`Move ${n.name} up`}>
                  <LuArrowUp />
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="size-7"
                  disabled={i === ordered.length - 1}
                  onClick={() => move(n.id, i + 1)}
                  aria-label={`Move ${n.name} down`}
                >
                  <LuArrowDown />
                </Button>
              </li>
            ))}
            {!ordered.length && <li className="px-3 py-4 text-center text-sm text-muted-foreground">No nodes enrolled.</li>}
          </ol>
        </div>

        <div className="space-y-1.5 rounded-md border bg-muted/30 p-3">
          <p className="text-sm font-medium">Pre-flight</p>
          <ul className="space-y-1 text-sm">
            {checks.map((c) => (
              <li key={c.text} className="flex items-start gap-2">
                {checkIcon[c.level]}
                <span>{c.text}</span>
              </li>
            ))}
          </ul>
        </div>

        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button onClick={start} disabled={blocked || create.isPending}>
            Start run
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
