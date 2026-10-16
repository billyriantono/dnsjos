import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useDeferredValue, useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { LuChevronLeft, LuChevronRight, LuHammer,
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
import { ProfileMultiSelect } from '@/pages/blocklist/ProfileMultiSelect'
import { profileSetLabel, sameProfiles } from '@/pages/blocklist/profiles'
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
  useBlocklistChanges,
  useBlocklistLookup,
  useBlocklistSource,
  useBlocklistProfiles,
  useBlocklistSources,
  useBuildNow,
  useCreateSource,
  useDeleteSource,
  useUpdateSource,
} from '@/lib/api/client'
import type { BlocklistBuild, BlocklistLookup, BlocklistProfile, BlocklistSource, BlocklistSourceCreate, BlocklistSourceKind, BlocklistSourcePatch } from '@/lib/api/types'
import { fmtBytes, fmtDateTime, fmtDuration, fmtNumber, shortSha } from '@/lib/format'
import { cn, looksLikeIP } from '@/lib/utils'

import { AllowDialog, AllowlistCard } from './Allowlist'
import { RpzCard } from './Rpz'

const KINDS: Record<BlocklistSourceKind, string> = {
  trustpositif_domains: 'TrustPositif domains',
  trustpositif_ips: 'TrustPositif IPs',
  url_domains: 'URL — domains',
  url_ips: 'URL — IPs',
  manual_domains: 'Manual domains',
  manual_ips: 'Manual IPs',
  rpz_domains: 'RPZ slave',
  whitelist: 'Whitelist',
}
const isManual = (k: BlocklistSourceKind) => k === 'manual_domains' || k === 'manual_ips' || k === 'whitelist'
const isSlave = (k: BlocklistSourceKind) => k === 'rpz_domains'

/** Sentinel for "all scopes". The global scope is a real empty string, so the selector needs
 * a distinct sentinel for it too (Radix Select forbids an empty item value). */
const ALL = '__all__'
const GLOBAL = '__global__'
/** Maps the selector's sentinel space to the API scope: undefined all, '' global, else profile. */
const scopeFor = (sel: string) => (sel === ALL ? undefined : sel === GLOBAL ? '' : sel)
const ownSources = (s: BlocklistSource, profileId: string) => s.profile_ids.includes(profileId)

const buildDuration = (b: BlocklistBuild) =>
  b.finished_at ? fmtDuration((new Date(b.finished_at).getTime() - new Date(b.started_at).getTime()) / 1000) : '—'

/** Builds + current poll every 2 s while a build is running, otherwise every 10 s. */
function useBuildState(profileId?: string) {
  const builds = useQuery({
    queryKey: qk.blocklistBuilds(profileId),
    queryFn: () => api.blocklist.builds(profileId),
    refetchInterval: (q) => (q.state.data?.items.some((b) => b.status === 'running') ? 2_000 : 10_000),
  })
  const running = builds.data?.items.some((b) => b.status === 'running') ?? false
  const current = useQuery({
    queryKey: qk.blocklistCurrent(profileId),
    queryFn: () => api.blocklist.current(profileId),
    refetchInterval: running ? 2_000 : 10_000,
  })
  // A build rewrites each source's entries / last fetch / status. Refetch sources whenever the newest build
  // changes id or status; keying on `running` alone misses builds that finish between two 10 s polls.
  const qc = useQueryClient()
  const newest = builds.data?.items[0]
  const newestKey = newest && `${newest.id}:${newest.status}`
  useEffect(() => {
    if (newestKey) void qc.invalidateQueries({ queryKey: qk.blocklistSourcesAll })
  }, [qc, newestKey])
  return { builds, current, running }
}

export default function BlocklistPage() {
  // The selector works in sentinel space (ALL / GLOBAL / a profile id): Radix Select rejects
  // an empty-string item value, but "" is a real scope. scopeFor() maps back to the API scope.
  const [selected, setSelected] = useState<string>(ALL)
  const profiles = useBlocklistProfiles()
  const scope: string | undefined = scopeFor(selected)
  const profile = scope !== undefined && scope !== '' ? profiles.data?.items.find((p) => p.id === scope) : undefined
  const { builds, current, running } = useBuildState(scope)
  const buildNow = useBuildNow()
  const busy = running || buildNow.isPending
  const [changesOf, setChangesOf] = useState<BlocklistBuild | null>(null)
  const runBuild = (force: boolean) =>
    buildNow.mutate(
      { force, profileId: scope },
      {
        onSuccess: (b) =>
          toast.success(
            force
              ? `Forced build #${b.id} started (full re-download)${b.profile_id ? ` for ${b.profile_name || b.profile_id}` : ''}`
              : `Build #${b.id} started${b.profile_id ? ` for ${b.profile_name || b.profile_id}` : ''}`,
          ),
        onError: toastError,
      },
    )
  const scopeLabel = scope === undefined ? 'All profiles' : scope === '' ? 'Global (shared)' : (profile?.name ?? scope)
  return (
    <>
      <PageHeader
        title="Blocklist"
        description="TrustPositif and custom lists, built once per profile into a CDB file that the profile's nodes download."
        actions={
          <RequireAdmin>
            <div className="flex flex-wrap gap-2">
              <Button
                variant="outline"
                disabled={busy}
                title="Ignore cached copies: download every source again and rebuild (useful to measure download speed)"
                onClick={() => runBuild(true)}
              >
                <LuRefreshCw className={busy ? 'animate-spin' : undefined} />
                Force re-download
              </Button>
              <Button disabled={busy} onClick={() => runBuild(false)}>
                <LuHammer className={busy ? 'animate-pulse' : undefined} />
                {busy ? 'Building…' : `Build now · ${scopeLabel}`}
              </Button>
            </div>
          </RequireAdmin>
        }
      />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <CurrentBuildCard build={current.data} loading={current.isPending} running={running} scope={scope} />
        <LookupCard />
      </div>
      <ProfilesCard
        profiles={profiles.data?.items}
        loading={profiles.isPending}
        error={profiles.error}
        selected={selected}
        onSelect={setSelected}
      />
      <AllowlistCard />
      <RpzCard />
      <SourcesCard scope={scope} profile={profile} />
      <Card>
        <CardHeader className="flex flex-row items-start justify-between gap-2">
          <div className="space-y-1.5">
            <CardTitle>Build history</CardTitle>
            <CardDescription>
              Newest first. The newest successful build is the one nodes on this scope download.
            </CardDescription>
          </div>
          <ScopeSelect selected={selected} onSelect={setSelected} profiles={profiles.data?.items} id="builds-scope" />
        </CardHeader>
        <CardContent>
          <DataTable
            columns={buildColumns(setChangesOf)}
            rows={builds.data?.items}
            loading={builds.isPending}
            error={builds.error}
            rowKey={(b) => b.id}
            defaultSort={{ key: 'id', desc: true }}
            empty={<EmptyState icon={LuHammer} title="No builds yet" description="The first build runs on schedule or via Build now." />}
          />
        </CardContent>
      </Card>
      {changesOf && <ChangesDialog build={changesOf} onClose={() => setChangesOf(null)} />}
    </>
  )
}

/** Scope picker: All profiles / Global (shared) / each config profile. */
function ScopeSelect({
  selected,
  onSelect,
  profiles,
  id,
  className,
}: {
  selected: string
  onSelect: (scope: string) => void
  profiles: BlocklistProfile[] | undefined
  id: string
  className?: string
}) {
  return (
    <Select value={selected} onValueChange={onSelect}>
      <SelectTrigger id={id} className={cn('w-56', className)} aria-label="Blocklist scope">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value={ALL}>All profiles</SelectItem>
        <SelectItem value={GLOBAL}>Global (shared)</SelectItem>
        {profiles?.map((p) => (
          <SelectItem key={p.id} value={p.id}>
            {p.name}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}

/** Every config profile with its blocklist scope, so an operator can jump into a profile's scope. */
function ProfilesCard({
  profiles,
  loading,
  error,
  selected,
  onSelect,
}: {
  profiles: BlocklistProfile[] | undefined
  loading: boolean
  error: Error | null
  selected: string
  onSelect: (scope: string) => void
}) {
  const columns: Column<BlocklistProfile>[] = [
    {
      key: 'name',
      header: 'Profile',
      sortValue: (p) => p.name,
      cell: (p) => (
        <div className="min-w-0">
          <div className="font-medium">{p.name}</div>
          {p.description && <div className="max-w-80 truncate text-xs text-muted-foreground">{p.description}</div>}
        </div>
      ),
    },
    { key: 'sources', header: 'Sources', align: 'right', sortValue: (p) => p.source_count, cell: (p) => fmtNumber(p.source_count) },
    {
      key: 'build',
      header: 'Build',
      sortValue: (p) => p.own_build?.id ?? -1,
      cell: (p) =>
        p.own_build ? (
          <span className="flex items-center gap-2">
            <StatusBadge status={p.own_build.status} />
            <span className="text-xs text-muted-foreground">#{p.own_build.id}</span>
          </span>
        ) : (
          <span className="text-xs text-muted-foreground">No own build</span>
        ),
    },
    {
      key: 'served',
      header: 'Served',
      cell: (p) =>
        p.uses_global ? (
          <Badge variant="secondary">Global build</Badge>
        ) : p.effective_build ? (
          <Badge variant="outline">Own build</Badge>
        ) : (
          <span className="text-xs text-muted-foreground">Nothing yet</span>
        ),
    },
    {
      key: 'manage',
      header: '',
      align: 'right',
      cell: (p) => (
        <Button variant="ghost" size="sm" disabled={selected === p.id} onClick={() => onSelect(p.id)}>
          {selected === p.id ? 'Selected' : 'Manage'}
        </Button>
      ),
    },
  ]
  return (
    <Card>
      <CardHeader>
        <CardTitle>Profiles</CardTitle>
        <CardDescription>
          Each config profile can have its own sources and build; profiles without an own build are served the global one.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <DataTable
          columns={columns}
          rows={profiles}
          loading={loading}
          error={error}
          rowKey={(p) => p.id}
          defaultSort={{ key: 'name' }}
          empty={<EmptyState title="No profiles" description="Create a config profile to give it its own blocklist." />}
        />
      </CardContent>
    </Card>
  )
}

const CHANGES_PAGE = 200

function ChangesDialog({ build, onClose }: { build: BlocklistBuild; onClose: () => void }) {
  const [q, setQ] = useState('')
  const [kind, setKind] = useState<'added' | 'removed' | ''>('')
  const [offset, setOffset] = useState(0)
  const query = useDeferredValue(q.trim().toLowerCase())
  const { data, isPending, isPlaceholderData, error } = useBlocklistChanges(build.id, { q: query, kind: kind || undefined, limit: CHANGES_PAGE, offset })
  const kinds = [
    { id: '', label: 'All', count: build.added + build.removed },
    { id: 'added', label: 'Added', count: build.added },
    { id: 'removed', label: 'Removed', count: build.removed },
  ] as const
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>
            Build #{build.id} changes · <span className="text-success">+{fmtNumber(build.added)}</span>{' '}
            <span className="text-destructive">−{fmtNumber(build.removed)}</span>
          </DialogTitle>
        </DialogHeader>
        <div className="flex gap-2">
          <div className="flex shrink-0 rounded-md border p-0.5" role="group" aria-label="Change type">
            {kinds.map((k) => (
              <Button
                key={k.id}
                type="button"
                size="sm"
                variant={kind === k.id ? 'secondary' : 'ghost'}
                className="h-8 px-2.5"
                aria-pressed={kind === k.id}
                onClick={() => {
                  setKind(k.id)
                  setOffset(0)
                }}
              >
                {k.label} <span className="tabular text-muted-foreground">{fmtNumber(k.count)}</span>
              </Button>
            ))}
          </div>
          <Input
            value={q}
            onChange={(e) => {
              setQ(e.target.value)
              setOffset(0)
            }}
            placeholder="Filter names"
            aria-label="Filter changed names"
          />
        </div>
        {isPending ? (
          <Skeleton className="h-40 w-full" />
        ) : error ? (
          <p className="text-sm text-destructive">{error.message}</p>
        ) : (
          <>
            <ul className={cn('max-h-96 overflow-y-auto rounded-md border font-mono text-xs', isPlaceholderData && 'opacity-60')}>
              {data.items.map((c) => (
                <li key={c.name} className="flex gap-2 border-b px-3 py-1.5 last:border-b-0">
                  <span className={c.added ? 'text-success' : 'text-destructive'}>{c.added ? '+' : '−'}</span>
                  <span className="break-all">{c.name}</span>
                </li>
              ))}
              {data.items.length === 0 && <li className="px-3 py-4 text-center text-muted-foreground">No matching names</li>}
            </ul>
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <p className="flex-1">
                {data.total ? `${fmtNumber(offset + 1)}–${fmtNumber(offset + data.items.length)}` : '0'} of {fmtNumber(data.total)}
                {!query && !kind && data.total < build.added + build.removed && ' (very large changes keep only the first 500,000 names each way)'}
              </p>
              <Button type="button" variant="outline" size="sm" disabled={offset === 0 || isPlaceholderData} onClick={() => setOffset(Math.max(0, offset - CHANGES_PAGE))}>
                <LuChevronLeft /> Prev
              </Button>
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={offset + CHANGES_PAGE >= data.total || isPlaceholderData}
                onClick={() => setOffset(offset + CHANGES_PAGE)}
              >
                Next <LuChevronRight />
              </Button>
            </div>
          </>
        )}
      </DialogContent>
    </Dialog>
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

function CurrentBuildCard({
  build,
  loading,
  running,
  scope,
}: {
  build: BlocklistBuild | null | undefined
  loading: boolean
  running: boolean
  scope: string | undefined
}) {
  const scopeLabel = scope === undefined ? 'all scopes' : scope === '' ? 'the global scope' : `profile ${build?.profile_name || scope}`
  return (
    <Card className="lg:col-span-2">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          Current build
          {build && <StatusBadge status={build.status} />}
          {(build?.profile_id || running) && (
            <Badge variant="outline">
              {build?.profile_id ? build.profile_name || build.profile_id : scope === '' ? 'global' : scopeLabel}
            </Badge>
          )}
          {running && <StatusBadge status="running" label="new build running" />}
        </CardTitle>
        <CardDescription>
          {build ? (
            <>
              #{build.id} · built <TimeAgo date={build.finished_at ?? build.started_at} /> · {build.trigger}
            </>
          ) : (
            `What nodes download right now for ${scopeLabel}.`
          )}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {loading ? (
          <Skeleton className="h-20 w-full" />
        ) : !build ? (
          <EmptyState
            icon={LuShieldBan}
            title="No blocklist published yet"
            description={`Nodes on ${scopeLabel} block nothing until a build here succeeds.`}
          />
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

const buildColumns = (onChanges: (b: BlocklistBuild) => void): Column<BlocklistBuild>[] => [
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
  {
    key: 'changes',
    header: 'Changes',
    align: 'right',
    cell: (b) =>
      b.status === 'ok' && (b.added || b.removed) ? (
        <button
          type="button"
          className="font-mono text-xs whitespace-nowrap underline-offset-4 hover:underline"
          title="Show the changed names"
          onClick={() => onChanges(b)}
        >
          <span className="text-success">+{fmtNumber(b.added)}</span>{' '}
          <span className="text-destructive">−{fmtNumber(b.removed)}</span>
        </button>
      ) : (
        <span className="text-muted-foreground">—</span>
      ),
    sortValue: (b) => b.added + b.removed,
  },
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
            {r.match !== r.name && ' (parent suffix)'} ·{' '}
            {r.blocked_since ? (
              <span title={fmtDateTime(r.blocked_since)}>
                listed since <TimeAgo date={r.blocked_since} />
              </span>
            ) : (
              'listed since before change tracking began'
            )}
          </div>
        )}
        {r.history.length > 0 && (
          <ul className="space-y-0.5 text-xs text-muted-foreground">
            {r.history.map((c) => (
              <li key={`${c.build_id}:${c.name}`}>
                <span className={c.added ? 'text-destructive' : 'text-success'}>{c.added ? 'added' : 'removed'}</span>{' '}
                <code className="font-mono break-all">{c.name}</code> · build #{c.build_id} · {fmtDateTime(c.at)}
              </li>
            ))}
          </ul>
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

function SourcesCard({ scope, profile }: { scope: string | undefined; profile: BlocklistProfile | undefined }) {
  const { isAdmin } = useAuth()
  const { data, isPending, error } = useBlocklistSources(scope)
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
          <div className="flex items-center gap-2">
            <span className="font-medium">{s.name}</span>
            {scope !== undefined && !ownSources(s, scope) && <Badge variant="secondary">inherited from global</Badge>}
          </div>
          <div className="max-w-80 truncate text-xs text-muted-foreground" title={s.url}>
            {isManual(s.kind) ? 'Manual list' : isSlave(s.kind) ? 'Pulled from an RPZ master' : s.url}
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
    {
      key: 'profile',
      header: 'Profiles',
      sortValue: (s) => s.profile_names.join(', '),
      cell: (s) => (
        <span className={s.profile_ids.length > 0 ? undefined : 'text-muted-foreground'}>
          {profileSetLabel(s.profile_names)}
        </span>
      ),
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
          <CardDescription>
            Every enabled source goes into the build; whitelist entries (and their subdomains) are removed.
            {profile &&
              (profile.uses_global
                ? ' This profile has no own build yet, so it is served the global one.'
                : ' This profile is served its own build.')}
          </CardDescription>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <Badge variant="outline">{scope === undefined ? 'All profiles' : scope === '' ? 'Global (shared)' : (profile?.name ?? scope)}</Badge>
          <RequireAdmin>
            <Button size="sm" onClick={() => setEditing('new')}>
              <LuPlus />
              Add source
            </Button>
          </RequireAdmin>
        </div>
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
      {editing && <SourceDialog source={editing === 'new' ? null : editing} profileId={scope} onClose={() => setEditing(null)} />}
    </Card>
  )
}

function SourceDialog({ source, profileId, onClose }: { source: BlocklistSource | null; profileId: string | undefined; onClose: () => void }) {
  const detail = useBlocklistSource(source?.id)
  const loaded = !source || !!detail.data
  const displayed = detail.data ?? source

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{displayed ? `Edit ${displayed.name}` : 'Add blocklist source'}</DialogTitle>
        </DialogHeader>
        {!loaded ? (
          detail.isError ? (
            <div className="grid gap-4">
              <div className="rounded-md border border-destructive/40 bg-destructive/5 p-3 text-sm">
                <p>Could not load the source contents.</p>
                <Button type="button" variant="outline" size="sm" className="mt-3" onClick={() => void detail.refetch()}>
                  Retry
                </Button>
              </div>
              <DialogFooter>
                <Button type="button" variant="outline" onClick={onClose}>
                  Cancel
                </Button>
              </DialogFooter>
            </div>
          ) : (
            <div className="grid gap-4">
              <div className="grid gap-3" aria-label="Loading source">
                <Skeleton className="h-10 w-full" />
                <Skeleton className="h-10 w-full" />
                <Skeleton className="h-40 w-full" />
              </div>
              <DialogFooter>
                <Button type="button" variant="outline" onClick={onClose}>
                  Cancel
                </Button>
              </DialogFooter>
            </div>
          )
        ) : (
          <SourceForm source={displayed} profileId={profileId} onClose={onClose} />
        )}
      </DialogContent>
    </Dialog>
  )
}

function SourceForm({ source, profileId, onClose }: { source: BlocklistSource | null; profileId: string | undefined; onClose: () => void }) {
  const profiles = useBlocklistProfiles()
  const [name, setName] = useState(source?.name ?? '')
  const [kind, setKind] = useState<BlocklistSourceKind>(source?.kind ?? 'url_domains')
  const [url, setUrl] = useState(source?.url ?? '')
  const [content, setContent] = useState(source?.content ?? '')
  const [enabled, setEnabled] = useState(source?.enabled ?? true)
  // The dialog edits the source's profile set directly ([] = global). A new source starts
  // from the page filter: a concrete profile preselects it, "all profiles" starts global.
  const [profileIds, setProfileIds] = useState<string[]>(
    source ? source.profile_ids : profileId && profileId !== '' ? [profileId] : [],
  )
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
    // A profile-set change is a scoped change the API treats specially ([] = global), so only
    // send profile_ids when the set actually differs from the source's own.
    const changed = source ? !sameProfiles(profileIds, source.profile_ids) : profileIds.length > 0
    const body: BlocklistSourceCreate & BlocklistSourcePatch = {
      name: name.trim(),
      kind,
      url: manual ? '' : url.trim(),
      content: manual ? content : '',
      enabled,
    }
    if (changed) body.profile_ids = profileIds
    if (source) update.mutate({ id: source.id, patch: body }, done)
    else create.mutate(body, done)
  }

  const lines = manual ? content.split('\n').filter((l) => l.trim() && !l.trim().startsWith('#')).length : 0
  return (
    <form onSubmit={submit} className="grid gap-4">
      <Field id="src-name" label="Name">
        <Input id="src-name" value={name} onChange={(e) => setName(e.target.value)} required />
      </Field>
      <Field
        id="src-profile"
        label="Profiles"
        hint={source ? 'Changing the profiles rebuilds the source for each one — the current build keeps it until the next build.' : 'Pick one or more profiles to build this source for them; leave empty to share it with every profile.'}
      >
        <ProfileMultiSelect id="src-profile" profiles={profiles.data?.items} value={profileIds} onChange={setProfileIds} />
      </Field>
      <Field id="src-kind" label="Kind" hint={source ? 'The kind cannot be changed after creation.' : undefined}>
        <Select value={kind} onValueChange={(v) => setKind(v as BlocklistSourceKind)} disabled={!!source}>
          <SelectTrigger id="src-kind" className="w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {Object.entries(KINDS)
              .filter(([k]) => !isSlave(k as BlocklistSourceKind))
              .map(([k, label]) => (
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
  )
}
