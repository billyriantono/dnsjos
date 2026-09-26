import { useState } from 'react'
import { LuArrowRight, LuGitCompareArrows } from 'react-icons/lu'

import { EmptyState } from '@/components/EmptyState'
import { Badge } from '@/components/ui/badge'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { useVersionDiff } from '@/lib/api/client'
import { normalizeSpec } from '@/lib/api/profiles'
import type { ConfigSpec, ConfigVersion } from '@/lib/api/types'
import { cn } from '@/lib/utils'

type Leaf = string | number | boolean | null | string[]

/** Flattens a spec to path → leaf. Lists of scalars stay whole (diffed as sets); lists of objects are indexed. */
function flatten(v: unknown, path = '', out = new Map<string, Leaf>()) {
  if (Array.isArray(v) && v.some((x) => typeof x === 'object' && x !== null)) v.forEach((x, i) => flatten(x, `${path}[${i}]`, out))
  else if (typeof v === 'object' && v !== null && !Array.isArray(v))
    for (const [k, x] of Object.entries(v)) flatten(x, path ? `${path}.${k}` : k, out)
  else out.set(path, Array.isArray(v) ? v.map(String) : (v as Leaf) ?? null)
  return out
}

interface Row {
  path: string
  a: Leaf | undefined
  b: Leaf | undefined
  changed: boolean
}

function diffRows(a: ConfigSpec, b: ConfigSpec): Row[] {
  const fa = flatten(normalizeSpec(a))
  const fb = flatten(normalizeSpec(b))
  const paths = [...fa.keys(), ...[...fb.keys()].filter((k) => !fa.has(k))]
  return paths.map((path) => {
    const x = fa.get(path)
    const y = fb.get(path)
    return { path, a: x, b: y, changed: JSON.stringify(x) !== JSON.stringify(y) }
  })
}

function Value({ v, other, side }: { v: Leaf | undefined; other: Leaf | undefined; side: 'a' | 'b' }) {
  if (v === undefined) return <span className="text-muted-foreground italic">absent</span>
  if (Array.isArray(v)) {
    const peer = new Set(Array.isArray(other) ? other : [])
    if (v.length === 0) return <span className="text-muted-foreground italic">empty list</span>
    return (
      <div className="flex flex-wrap gap-1">
        {v.map((x, i) => {
          const diff = !peer.has(x)
          return (
            <span
              key={i}
              className={cn(
                'rounded px-1 font-mono text-xs',
                diff ? (side === 'a' ? 'bg-destructive/15 text-destructive line-through' : 'bg-success/15 text-success') : 'bg-muted',
              )}
            >
              {x}
            </span>
          )
        })}
      </div>
    )
  }
  const text = v === '' ? '""' : String(v)
  return <span className="font-mono text-xs break-all whitespace-pre-wrap">{text}</span>
}

/** Side-by-side structured diff of two specs. */
export function SpecDiff({ a, b, showUnchanged }: { a: ConfigSpec; b: ConfigSpec; showUnchanged?: boolean }) {
  const rows = diffRows(a, b)
  const visible = showUnchanged ? rows : rows.filter((r) => r.changed)
  if (!visible.length) return <EmptyState icon={LuGitCompareArrows} title="No differences" description="Both versions have the same configuration." />
  return (
    <div className="overflow-hidden rounded-md border">
      <div className="grid grid-cols-[minmax(10rem,14rem)_1fr_1fr] border-b bg-muted/40 text-xs font-medium text-muted-foreground">
        <div className="px-3 py-2">Field</div>
        <div className="border-l px-3 py-2">Before</div>
        <div className="border-l px-3 py-2">After</div>
      </div>
      {visible.map((r) => (
        <div key={r.path} className={cn('grid grid-cols-[minmax(10rem,14rem)_1fr_1fr] border-b last:border-b-0 text-sm', !r.changed && 'opacity-60')}>
          <div className="px-3 py-2 font-mono text-xs break-all text-muted-foreground">{r.path}</div>
          <div className={cn('border-l px-3 py-2', r.changed && !Array.isArray(r.a) && 'bg-destructive/10')}>
            <Value v={r.a} other={r.b} side="a" />
          </div>
          <div className={cn('border-l px-3 py-2', r.changed && !Array.isArray(r.b) && 'bg-success/10')}>
            <Value v={r.b} other={r.a} side="b" />
          </div>
        </div>
      ))}
    </div>
  )
}

function VersionSelect({ versions, value, onChange, label }: { versions: ConfigVersion[]; value: number; onChange: (v: number) => void; label: string }) {
  return (
    <div className="grid gap-1.5">
      <Label className="text-xs text-muted-foreground">{label}</Label>
      <Select value={String(value)} onValueChange={(v) => onChange(Number(v))}>
        <SelectTrigger className="w-56" aria-label={`${label} version`}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {versions.map((v) => (
            <SelectItem key={v.version} value={String(v.version)}>
              v{v.version}
              {v.published && <span className="text-success">· published</span>}
              {v.comment && <span className="max-w-32 truncate text-muted-foreground">· {v.comment}</span>}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  )
}

/** Compare any two versions of a profile (fetched through GET …/versions/{a}/diff/{b}). */
export function VersionDiffDialog({
  profileId,
  versions,
  pair,
  onClose,
}: {
  profileId: string
  versions: ConfigVersion[]
  pair: [number, number] | null
  onClose: () => void
}) {
  return (
    <Dialog open={pair !== null} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-6xl">
        <DialogHeader>
          <DialogTitle>Compare versions</DialogTitle>
          <DialogDescription>Only changed fields are shown unless you include unchanged ones.</DialogDescription>
        </DialogHeader>
        {pair && <DiffBody key={pair.join('-')} profileId={profileId} versions={versions} initial={pair} />}
      </DialogContent>
    </Dialog>
  )
}

function DiffBody({ profileId, versions, initial }: { profileId: string; versions: ConfigVersion[]; initial: [number, number] }) {
  const [[a, b], setPair] = useState(initial)
  const [all, setAll] = useState(false)
  const diff = useVersionDiff(profileId, a, b)
  return (
    <div className="grid gap-4">
      <div className="flex flex-wrap items-end gap-3">
        <VersionSelect label="Before" versions={versions} value={a} onChange={(v) => setPair([v, b])} />
        <LuArrowRight className="mb-2.5 text-muted-foreground" />
        <VersionSelect label="After" versions={versions} value={b} onChange={(v) => setPair([a, v])} />
        <label className="mb-2 ml-auto flex items-center gap-2 text-sm">
          <Switch checked={all} onCheckedChange={setAll} /> Show unchanged
        </label>
      </div>
      {diff.data ? (
        <>
          <div className="grid grid-cols-2 gap-3 text-xs text-muted-foreground">
            {[diff.data.a, diff.data.b].map((v) => (
              <p key={v.version} className="truncate">
                <Badge variant="outline" className="mr-1.5">v{v.version}</Badge>
                {v.comment || 'no comment'}
              </p>
            ))}
          </div>
          <p className="text-xs text-muted-foreground">
            {diff.data.changes.length} change{diff.data.changes.length === 1 ? '' : 's'}
          </p>
          <SpecDiff a={diff.data.a.spec} b={diff.data.b.spec} showUnchanged={all} />
        </>
      ) : diff.isError ? (
        <p className="text-sm text-destructive">{diff.error.message}</p>
      ) : (
        <div className="grid gap-2">
          {Array.from({ length: 6 }, (_, i) => (
            <Skeleton key={i} className="h-8 w-full" />
          ))}
        </div>
      )}
    </div>
  )
}
