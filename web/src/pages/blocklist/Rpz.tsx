import { useState, type FormEvent } from 'react'
import { LuPlus, LuPencil, LuRefreshCw, LuTrash2 } from 'react-icons/lu'
import { toast } from 'sonner'

import { RequireAdmin, useAuth } from '@/app/auth'
import { ConfirmDialog } from '@/components/ConfirmDialog'
import { DataTable, type Column } from '@/components/DataTable'
import { EmptyState } from '@/components/EmptyState'
import { Field } from '@/components/ops/Field'
import { ProfileMultiSelect } from '@/pages/blocklist/ProfileMultiSelect'
import { profileSetLabel, sameProfiles } from '@/pages/blocklist/profiles'
import { toastError } from '@/components/ops/toast'
import { TimeAgo } from '@/components/TimeAgo'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import {
  useBlocklistProfiles,
  useCreateRPZUpstream,
  useDeleteRPZUpstream,
  useRPZUpstreams,
  useSyncRPZUpstream,
  useUpdateRPZUpstream,
} from '@/lib/api/client'
import type { RPZUpstream, RPZUpstreamCreate } from '@/lib/api/types'
import { fmtNumber } from '@/lib/format'

/**
 * RPZ slave management (SPEC §7.7): each upstream is an RPZ master the panel pulls the
 * blocklist zone from over AXFR/IXFR. An upstream owns a source of kind rpz_domains, so it
 * shows up in the Sources table too — this card is where it is created and synced.
 */
export function RpzCard() {
  const { isAdmin } = useAuth()
  const { data, isPending, error } = useRPZUpstreams()
  const sync = useSyncRPZUpstream()
  const remove = useDeleteRPZUpstream()
  const [editing, setEditing] = useState<RPZUpstream | 'new' | null>(null)

  const columns: Column<RPZUpstream>[] = [
    {
      key: 'name',
      header: 'Name',
      sortValue: (u) => u.name,
      cell: (u) => (
        <div className="min-w-0">
          <div className="font-medium">{u.name}</div>
          <div className="max-w-80 truncate text-xs text-muted-foreground" title={`${u.upstream} ${u.zone}`}>
            {u.upstream} · {u.zone}
          </div>
        </div>
      ),
    },
    {
      key: 'profile',
      header: 'Profiles',
      sortValue: (u) => u.profile_names.join(', '),
      cell: (u) => (
        <span className={u.profile_ids.length > 0 ? undefined : 'text-muted-foreground'}>
          {profileSetLabel(u.profile_names)}
        </span>
      ),
    },
    {
      key: 'serial',
      header: 'Serial',
      align: 'right',
      sortValue: (u) => u.serial,
      cell: (u) => <span className="font-mono text-xs">{u.serial}</span>,
    },
    { key: 'domains', header: 'Domains', align: 'right', sortValue: (u) => u.total_domains, cell: (u) => fmtNumber(u.total_domains) },
    {
      key: 'tsig',
      header: 'TSIG',
      sortValue: (u) => u.has_tsig,
      cell: (u) => <Badge variant={u.has_tsig ? 'secondary' : 'outline'}>{u.has_tsig ? 'TSIG' : 'none'}</Badge>,
    },
    {
      key: 'last',
      header: 'Last sync',
      sortValue: (u) => u.last_sync_at,
      cell: (u) => (u.last_sync_at ? <TimeAgo date={u.last_sync_at} /> : <span className="text-muted-foreground">never</span>),
    },
    {
      key: 'status',
      header: 'Status',
      className: 'max-w-56',
      cell: (u) => (
        <span className={u.last_error ? 'block truncate text-xs text-destructive' : 'block truncate text-xs text-muted-foreground'} title={u.last_error}>
          {u.last_error || `${u.interval_s}s interval`}
        </span>
      ),
    },
  ]
  if (isAdmin)
    columns.push({
      key: 'actions',
      header: '',
      align: 'right',
      cell: (u) => (
        <div className="flex justify-end gap-1">
          <Button
            variant="ghost"
            size="icon"
            className="size-8"
            aria-label="Sync now"
            title="Pull the zone now"
            disabled={sync.isPending}
            onClick={() =>
              sync.mutate(u.id, {
                onSuccess: (r) => toast.success(`${u.name} synced (serial ${r.serial})`),
                onError: toastError,
              })
            }
          >
            <LuRefreshCw className={sync.isPending && sync.variables === u.id ? 'animate-spin' : undefined} />
          </Button>
          <Button variant="ghost" size="icon" className="size-8" aria-label="Edit" onClick={() => setEditing(u)}>
            <LuPencil />
          </Button>
          <ConfirmDialog
            title={`Delete ${u.name}?`}
            description="The paired blocklist source is removed too; the next build will no longer include it."
            confirmLabel="Delete"
            destructive
            onConfirm={() => remove.mutateAsync(u.id).then(() => toast.success(`${u.name} deleted`), toastError)}
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
          <CardTitle>RPZ masters</CardTitle>
          <CardDescription>
            The panel pulls each zone from its master over AXFR/IXFR into a blocklist source, so the usual
            build turns it into a per-profile CDB. Only the panel needs the master's allow-IP and TSIG key.
          </CardDescription>
        </div>
        <RequireAdmin>
          <Button size="sm" onClick={() => setEditing('new')}>
            <LuPlus />
            Add master
          </Button>
        </RequireAdmin>
      </CardHeader>
      <CardContent>
        <DataTable
          columns={columns}
          rows={data?.items}
          loading={isPending}
          error={error}
          rowKey={(u) => u.id}
          defaultSort={{ key: 'name' }}
          empty={<EmptyState title="No RPZ masters" description="Add an RPZ master to pull its zone as a blocklist source." />}
        />
      </CardContent>
      {editing && <RpzDialog upstream={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
    </Card>
  )
}

function RpzDialog({ upstream, onClose }: { upstream: RPZUpstream | null; onClose: () => void }) {
  const profiles = useBlocklistProfiles()
  const create = useCreateRPZUpstream()
  const update = useUpdateRPZUpstream()
  const [name, setName] = useState(upstream?.name ?? '')
  const [host, setHost] = useState(upstream?.upstream ?? '')
  const [zone, setZone] = useState(upstream?.zone ?? '')
  const [interval, setIntervalS] = useState(String(upstream?.interval_s ?? 900))
  // TSIG secret is write-only: blank on edit means "keep the current secret".
  const [tsigKey, setTsigKey] = useState('')
  const [tsigSecret, setTsigSecret] = useState('')
  const [profileIds, setProfileIds] = useState<string[]>(upstream ? upstream.profile_ids : [])
  const pending = create.isPending || update.isPending

  const submit = (e: FormEvent) => {
    e.preventDefault()
    const seconds = Number.parseInt(interval, 10)
    if (!Number.isFinite(seconds) || seconds < 60 || seconds > 86400) {
      toast.error('Interval must be between 60 and 86400 seconds')
      return
    }
    if (tsigSecret && !tsigKey) {
      toast.error('TSIG key is required when a secret is set')
      return
    }
    const done = { onSuccess: () => { toast.success(upstream ? 'RPZ master saved' : 'RPZ master added'); onClose() }, onError: toastError }
    const tsigField = tsigKey ? { tsig_key: tsigKey, tsig_secret: tsigSecret } : {}
    // Only send profile_ids when the set actually changed, so an unrelated edit does not
    // needlessly wipe the source's transferred content and cache.
    const profileChanged = upstream ? !sameProfiles(profileIds, upstream.profile_ids) : profileIds.length > 0
    if (upstream) {
      // Only send tsig_* when the admin typed a key; sending "" clears TSIG.
      update.mutate({ id: upstream.id, patch: { name: name.trim(), upstream: host.trim(), zone: zone.trim(), interval_s: seconds, ...(profileChanged ? { profile_ids: profileIds } : {}), ...tsigField } }, done)
    } else {
      const body: RPZUpstreamCreate = {
        name: name.trim(),
        upstream: host.trim(),
        zone: zone.trim(),
        interval_s: seconds,
        profile_ids: profileIds,
        ...tsigField,
      }
      create.mutate(body, done)
    }
  }

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{upstream ? `Edit ${upstream.name}` : 'Add RPZ master'}</DialogTitle>
        </DialogHeader>
        <form onSubmit={submit} className="grid gap-4">
          <Field id="rpz-name" label="Name">
            <Input id="rpz-name" value={name} onChange={(e) => setName(e.target.value)} required />
          </Field>
          <Field id="rpz-host" label="Upstream" hint="host or host:port of the RPZ master (default port 53).">
            <Input id="rpz-host" value={host} onChange={(e) => setHost(e.target.value)} placeholder="10.0.0.1:53" required />
          </Field>
          <Field id="rpz-zone" label="Zone" hint="The RPZ zone name; a trailing dot is added automatically.">
            <Input id="rpz-zone" value={zone} onChange={(e) => setZone(e.target.value)} placeholder="rpz.komdigi.go.id" required />
          </Field>
          <Field id="rpz-profile" label="Profiles" hint="Pick one or more profiles to build this zone for; leave empty to share it with every profile.">
            <ProfileMultiSelect id="rpz-profile" profiles={profiles.data?.items} value={profileIds} onChange={setProfileIds} />
          </Field>
          <Field id="rpz-interval" label="Interval (seconds)" hint="How often to check the master for a newer serial (60–86400).">
            <Input id="rpz-interval" type="number" min={60} max={86400} value={interval} onChange={(e) => setIntervalS(e.target.value)} required />
          </Field>
          <div className="grid grid-cols-2 gap-4">
            <Field id="rpz-tsig-key" label="TSIG key" hint={upstream ? 'Leave blank to keep the current TSIG setting.' : 'Optional.'}>
              <Input id="rpz-tsig-key" value={tsigKey} onChange={(e) => setTsigKey(e.target.value)} placeholder="sync.key." />
            </Field>
            <Field id="rpz-tsig-secret" label="TSIG secret" hint="Base64.">
              <Input id="rpz-tsig-secret" type="password" value={tsigSecret} onChange={(e) => setTsigSecret(e.target.value)} placeholder="base64…" />
            </Field>
          </div>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={pending}>
              {upstream ? 'Save' : 'Add'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
