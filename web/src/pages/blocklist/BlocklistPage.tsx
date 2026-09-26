import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { LuHammer,
  LuRefreshCw, LuPencil, LuPlus, LuSearch, LuShieldBan, LuShieldCheck, LuTrash2 } from 'react-icons/lu'
import { toast } from 'sonner'

import { RequireAdmin, useAuth } from '@/app/auth'
import { ConfirmDialog } from '@/components/ConfirmDialog'
import { CopyButton } from '@/components/CopyButton'
import { DataTable, type Column } from '@/components/DataTable'
import { EmptyState } from '@/components/EmptyState'
import { Field } from '@/components/ops/Field'
import { toastError } from '@/components/ops/toast'
import { PageHeader } from '@/components/PageHeader'
import { StatusBadge } from '@/components/StatusBadge'
import { TimeAgo } from '@/components/TimeAgo'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import {
  api,
  qk,
  useBlocklistLookup,
  useBlocklistSources,
  useBuildNow,
  useCreateSource,
  useDeleteSource,
  useUpdateSource,
} from '@/lib/api/client'
import type { BlocklistBuild, BlocklistLookup, BlocklistSource, BlocklistSourceKind } from '@/lib/api/types'
import { fmtBytes, fmtDuration, fmtNumber, shortSha } from '@/lib/format'
import { looksLikeIP } from '@/lib/utils'

import { AllowDialog, AllowlistCard } from './Allowlist'

const KINDS: Record<BlocklistSourceKind, string> = {
  trustpositif_domains: 'TrustPositif domains',
  trustpositif_ips: 'TrustPositif IPs',
  url_domains: 'URL — domains',
  url_ips: 'URL — IPs',
  manual_domains: 'Manual domains',
  manual_ips: 'Manual IPs',
  whitelist: 'Whitelist',
}
const isManual = (k: BlocklistSourceKind) => k === 'manual_domains' || k === 'manual_ips' || k === 'whitelist'

const buildDuration = (b: BlocklistBuild) =>
  b.finished_at ? fmtDuration((new Date(b.finished_at).getTime() - new Date(b.started_at).getTime()) / 1000) : '—'

/** Builds + current poll every 2 s while a build is running, otherwise every 10 s. */
function useBuildState() {
  const builds = useQuery({
    queryKey: qk.blocklistBuilds,
    queryFn: api.blocklist.builds,
    refetchInterval: (q) => (q.state.data?.items.some((b) => b.status === 'running') ? 2_000 : 10_000),
  })
  const running = builds.data?.items.some((b) => b.status === 'running') ?? false
  const current = useQuery({
    queryKey: qk.blocklistCurrent,
    queryFn: api.blocklist.current,
    refetchInterval: running ? 2_000 : 10_000,
  })
  // A build rewrites each source's entries / last fetch / status. Refetch sources whenever the newest build
  // changes id or status; keying on `running` alone misses builds that finish between two 10 s polls.
  const qc = useQueryClient()
  const newest = builds.data?.items[0]
  const newestKey = newest && `${newest.id}:${newest.status}`
  useEffect(() => {
    if (newestKey) void qc.invalidateQueries({ queryKey: qk.blocklistSources })
  }, [qc, newestKey])
  return { builds, current, running }
}

export default function BlocklistPage() {
  const { builds, current, running } = useBuildState()
  const buildNow = useBuildNow()
  const busy = running || buildNow.isPending
  return (
    <>
      <PageHeader
        title="Blocklist"
        description="TrustPositif and custom lists, built once into a CDB file that every node downloads."
        actions={
          <RequireAdmin>
            <div className="flex flex-wrap gap-2">
              <Button
                variant="outline"
                disabled={busy}
                title="Ignore cached copies: download every source again and rebuild (useful to measure download speed)"
                onClick={() =>
                  buildNow.mutate(true, {
                    onSuccess: (b) => toast.success(`Forced build #${b.id} started (full re-download)`),
                    onError: toastError,
                  })
                }
              >
                <LuRefreshCw className={busy ? 'animate-spin' : undefined} />
                Force re-download
              </Button>
              <Button
                disabled={busy}
                onClick={() =>
                  buildNow.mutate(false, {
                    onSuccess: (b) => toast.success(`Build #${b.id} started`),
                    onError: toastError,
                  })
                }
              >
                <LuHammer className={busy ? 'animate-pulse' : undefined} />
                {busy ? 'Building…' : 'Build now'}
              </Button>
            </div>
          </RequireAdmin>
        }
      />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <CurrentBuildCard build={current.data} loading={current.isPending} running={running} />
        <LookupCard />
      </div>
      <AllowlistCard />
      <SourcesCard />
      <Card>
        <CardHeader>
          <CardTitle>Build history</CardTitle>
          <CardDescription>Newest first. The newest successful build is the one nodes download.</CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={buildColumns}
            rows={builds.data?.items}
            loading={builds.isPending}
            error={builds.error}
            rowKey={(b) => b.id}
            defaultSort={{ key: 'id', desc: true }}
            empty={<EmptyState icon={LuHammer} title="No builds yet" description="The first build runs on schedule or via Build now." />}
          />
        </CardContent>
      </Card>
    </>
  )
}

function Stat({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="tabular text-lg font-semibold">{children}</div>
    </div>
  )
}

function CurrentBuildCard({ build, loading, running }: { build: BlocklistBuild | null | undefined; loading: boolean; running: boolean }) {
  return (
    <Card className="lg:col-span-2">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          Current build
          {build && <StatusBadge status={build.status} />}
          {running && <StatusBadge status="running" label="new build running" />}
        </CardTitle>
        <CardDescription>
          {build ? (
            <>
              #{build.id} · built <TimeAgo date={build.finished_at ?? build.started_at} /> · {build.trigger}
            </>
          ) : (
            'What nodes are serving right now.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {loading ? (
          <Skeleton className="h-20 w-full" />
        ) : !build ? (
          <EmptyState icon={LuShieldBan} title="No blocklist published yet" description="Nodes block nothing until the first build succeeds." />
        ) : (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <Stat label="Entries">{fmtNumber(build.domains + build.ips)}</Stat>
              <Stat label="Domains">{fmtNumber(build.domains)}</Stat>
              <Stat label="IPs">{fmtNumber(build.ips)}</Stat>
              <Stat label="Size">{fmtBytes(build.size_bytes)}</Stat>
            </div>
            <div className="flex items-center gap-2 rounded-md border bg-muted/40 px-3 py-2">
              <span className="text-xs text-muted-foreground">sha256</span>
              <code className="min-w-0 flex-1 truncate font-mono text-xs">{build.sha256}</code>
              <CopyButton value={build.sha256} className="size-7" />
            </div>
            <p className="text-xs text-muted-foreground">
              {fmtNumber(build.whitelisted)} whitelisted · {fmtNumber(build.skipped)} skipped
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

const buildColumns: Column<BlocklistBuild>[] = [
  { key: 'id', header: '#', cell: (b) => b.id, sortValue: (b) => b.id },
  {
    key: 'status',
    header: 'Status',
    cell: (b) => <StatusBadge status={b.status} />,
    sortValue: (b) => b.status,
  },
  { key: 'trigger', header: 'Trigger', cell: (b) => <span className="capitalize">{b.trigger}</span>, sortValue: (b) => b.trigger },
  { key: 'started', header: 'Started', cell: (b) => <TimeAgo date={b.started_at} />, sortValue: (b) => b.started_at },
  { key: 'dur', header: 'Duration', cell: buildDuration },
  { key: 'domains', header: 'Domains', align: 'right', cell: (b) => fmtNumber(b.domains), sortValue: (b) => b.domains },
  { key: 'ips', header: 'IPs', align: 'right', cell: (b) => fmtNumber(b.ips), sortValue: (b) => b.ips },
  { key: 'wl', header: 'Whitelisted', align: 'right', cell: (b) => fmtNumber(b.whitelisted), sortValue: (b) => b.whitelisted },
  { key: 'size', header: 'Size', align: 'right', cell: (b) => fmtBytes(b.size_bytes), sortValue: (b) => b.size_bytes },
  { key: 'sha', header: 'sha256', cell: (b) => <code className="font-mono text-xs">{shortSha(b.sha256)}</code> },
  {
    key: 'error',
    header: 'Error',
    className: 'max-w-72',
    cell: (b) =>
      b.error ? (
        <span className="block truncate text-destructive" title={b.error}>
          {b.error}
        </span>
      ) : null,
  },
]

function LookupCard() {
  const [input, setInput] = useState('')
  const [name, setName] = useState('')
  const q = useBlocklistLookup(name)
  const [allowing, setAllowing] = useState(false)
  const submit = (e: FormEvent) => {
    e.preventDefault()
    setName(input.trim().toLowerCase())
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle>Lookup</CardTitle>
        <CardDescription>Check a domain or IPv4 against the current build (includes parent domains) and the allowlist.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <form onSubmit={submit} className="flex gap-2">
          <Input value={input} onChange={(e) => setInput(e.target.value)} placeholder="example.com or 1.2.3.4" aria-label="Domain or IPv4 to look up" />
          <Button type="submit" variant="secondary" disabled={!input.trim()}>
            <LuSearch />
            Check
          </Button>
        </form>
        <div aria-live="polite">
          {q.isFetching ? (
            <Skeleton className="h-14 w-full" />
          ) : q.error ? (
            <p className="text-sm text-destructive">{q.error.message}</p>
          ) : q.data ? (
            <LookupResult r={q.data} onAllow={() => setAllowing(true)} />
          ) : null}
        </div>
        {allowing && q.data && (
          <AllowDialog initial={{ kind: looksLikeIP(q.data.name) ? 'ip' : 'domain', value: q.data.name }} onClose={() => setAllowing(false)} />
        )}
      </CardContent>
    </Card>
  )
}

function LookupResult({ r, onAllow }: { r: BlocklistLookup; onAllow: () => void }) {
  const allowed = r.blocked && r.allowed
  const tone = allowed ? 'border-warning/30 bg-warning/10' : r.blocked ? 'border-destructive/30 bg-destructive/10' : 'border-success/30 bg-success/10'
  const Icon = r.blocked && !allowed ? LuShieldBan : LuShieldCheck
  return (
    <div className={'flex items-start gap-3 rounded-md border p-3 ' + tone}>
      <Icon className={'mt-0.5 size-5 shrink-0 ' + (allowed ? 'text-warning' : r.blocked ? 'text-destructive' : 'text-success')} aria-hidden />
      <div className="min-w-0 space-y-1 text-sm">
        <div className="font-medium break-all">
          {r.name} {allowed ? 'is on the blocklist but allowed' : r.blocked ? 'is blocked' : 'is not blocked'}
        </div>
        {r.blocked && (
          <div className="text-muted-foreground">
            matched <code className="font-mono break-all">{r.match}</code>
            {r.match !== r.name && ' (parent suffix)'}
          </div>
        )}
        {r.allow_entry && (
          <div className="text-muted-foreground">
            allowed by <code className="font-mono break-all">{r.allow_entry.value}</code>
            {r.allow_entry.reason && <> · {r.allow_entry.reason}</>}
            {r.allow_entry.created_by_email && <> · {r.allow_entry.created_by_email}</>} ·{' '}
            {r.allow_entry.expires_at ? (
              <>
                expires <TimeAgo date={r.allow_entry.expires_at} />
              </>
            ) : (
              'no expiry'
            )}
          </div>
        )}
        {r.blocked && !allowed && (
          <RequireAdmin>
            <Button size="sm" variant="outline" className="mt-1" onClick={onAllow}>
              <LuShieldCheck />
              {looksLikeIP(r.name) ? 'Allow this IP' : 'Allow this domain'}
            </Button>
          </RequireAdmin>
        )}
      </div>
    </div>
  )
}

function SourcesCard() {
  const { isAdmin } = useAuth()
  const { data, isPending, error } = useBlocklistSources()
  const update = useUpdateSource()
  const remove = useDeleteSource()
  const [editing, setEditing] = useState<BlocklistSource | 'new' | null>(null)

  const columns: Column<BlocklistSource>[] = [
    {
      key: 'name',
      header: 'Name',
      sortValue: (s) => s.name,
      cell: (s) => (
        <div className="min-w-0">
          <div className="font-medium">{s.name}</div>
          <div className="max-w-80 truncate text-xs text-muted-foreground" title={s.url}>
            {isManual(s.kind) ? 'Manual list' : s.url}
          </div>
        </div>
      ),
    },
    {
      key: 'kind',
      header: 'Kind',
      sortValue: (s) => s.kind,
      cell: (s) => <Badge variant={s.kind === 'whitelist' ? 'secondary' : 'outline'}>{KINDS[s.kind]}</Badge>,
    },
    { key: 'entries', header: 'Entries', align: 'right', sortValue: (s) => s.entries, cell: (s) => fmtNumber(s.entries) },
    { key: 'fetch', header: 'Last fetch', sortValue: (s) => s.last_fetch_at, cell: (s) => (isManual(s.kind) ? '—' : <TimeAgo date={s.last_fetch_at} />) },
    {
      key: 'status',
      header: 'Status',
      className: 'max-w-56',
      cell: (s) => (
        <span className="block truncate text-xs text-muted-foreground" title={s.last_status}>
          {s.last_status || '—'}
        </span>
      ),
    },
    {
      key: 'enabled',
      header: 'Enabled',
      sortValue: (s) => s.enabled,
      cell: (s) => (
        <Switch
          checked={s.enabled}
          disabled={!isAdmin || update.isPending}
          aria-label={`${s.name} enabled`}
          onCheckedChange={(enabled) =>
            update.mutate(
              { id: s.id, patch: { enabled } },
              { onSuccess: () => toast.success(`${s.name} ${enabled ? 'enabled' : 'disabled'}`), onError: toastError },
            )
          }
        />
      ),
    },
  ]
  if (isAdmin)
    columns.push({
      key: 'actions',
      header: '',
      align: 'right',
      cell: (s) => (
        <div className="flex justify-end gap-1">
          <Button variant="ghost" size="icon" className="size-8" aria-label="Edit" onClick={() => setEditing(s)}>
            <LuPencil />
          </Button>
          <ConfirmDialog
            title={`Delete ${s.name}?`}
            description="The next build will no longer include this source."
            confirmLabel="Delete"
            destructive
            onConfirm={() =>
              remove.mutateAsync(s.id).then(() => toast.success(`${s.name} deleted`), toastError)
            }
          >
            <Button variant="ghost" size="icon" className="size-8 text-destructive" aria-label="Delete">
              <LuTrash2 />
            </Button>
          </ConfirmDialog>
        </div>
      ),
    })

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-2">
        <div className="space-y-1.5">
          <CardTitle>Sources</CardTitle>
          <CardDescription>Every enabled source goes into each build; whitelist entries (and their subdomains) are removed.</CardDescription>
        </div>
        <RequireAdmin>
          <Button size="sm" onClick={() => setEditing('new')}>
            <LuPlus />
            Add source
          </Button>
        </RequireAdmin>
      </CardHeader>
      <CardContent>
        <DataTable
          columns={columns}
          rows={data?.items}
          loading={isPending}
          error={error}
          rowKey={(s) => s.id}
          defaultSort={{ key: 'name' }}
          empty={<EmptyState title="No sources" description="Add TrustPositif, a URL list or a manual list." />}
        />
      </CardContent>
      {editing && <SourceDialog source={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
    </Card>
  )
}

function SourceDialog({ source, onClose }: { source: BlocklistSource | null; onClose: () => void }) {
  const [name, setName] = useState(source?.name ?? '')
  const [kind, setKind] = useState<BlocklistSourceKind>(source?.kind ?? 'url_domains')
  const [url, setUrl] = useState(source?.url ?? '')
  const [content, setContent] = useState(source?.content ?? '')
  const [enabled, setEnabled] = useState(source?.enabled ?? true)
  const create = useCreateSource()
  const update = useUpdateSource()
  const manual = isManual(kind)
  const pending = create.isPending || update.isPending

  const submit = (e: FormEvent) => {
    e.preventDefault()
    const done = {
      onSuccess: () => {
        toast.success(source ? 'Source saved' : 'Source added')
        onClose()
      },
      onError: toastError,
    }
    const body = { name: name.trim(), url: manual ? '' : url.trim(), content: manual ? content : '', enabled }
    if (source) update.mutate({ id: source.id, patch: body }, done)
    else create.mutate({ ...body, kind }, done)
  }

  const lines = manual ? content.split('\n').filter((l) => l.trim() && !l.trim().startsWith('#')).length : 0
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{source ? `Edit ${source.name}` : 'Add blocklist source'}</DialogTitle>
        </DialogHeader>
        <form onSubmit={submit} className="grid gap-4">
          <Field id="src-name" label="Name">
            <Input id="src-name" value={name} onChange={(e) => setName(e.target.value)} required />
          </Field>
          <Field id="src-kind" label="Kind" hint={source ? 'The kind cannot be changed after creation.' : undefined}>
            <Select value={kind} onValueChange={(v) => setKind(v as BlocklistSourceKind)} disabled={!!source}>
              <SelectTrigger id="src-kind" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {Object.entries(KINDS).map(([k, label]) => (
                  <SelectItem key={k} value={k}>
                    {label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          {manual ? (
            <Field
              id="src-content"
              label={kind === 'whitelist' ? 'Whitelisted domains' : 'Entries'}
              hint={`One ${kind === 'manual_ips' ? 'IPv4 or CIDR (≤ /24)' : 'domain'} per line; # starts a comment. ${lines} entries.`}
            >
              <Textarea
                id="src-content"
                value={content}
                onChange={(e) => setContent(e.target.value)}
                rows={10}
                className="max-h-80 font-mono text-xs"
                placeholder={kind === 'manual_ips' ? '203.0.113.7\n198.51.100.0/24' : 'example.com\nbad.example.net'}
              />
            </Field>
          ) : (
            <Field id="src-url" label="URL" hint="Fetched on every build with If-None-Match / If-Modified-Since.">
              <Input id="src-url" type="url" value={url} onChange={(e) => setUrl(e.target.value)} required placeholder="https://…" />
            </Field>
          )}
          <label className="flex items-center gap-2 text-sm">
            <Switch checked={enabled} onCheckedChange={setEnabled} />
            Enabled
          </label>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={pending || !name.trim()}>
              {source ? 'Save' : 'Add source'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
