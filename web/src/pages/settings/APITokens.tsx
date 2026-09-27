import { useState, type FormEvent } from 'react'
import { LuKeyRound, LuPlus, LuTriangleAlert, LuTrash2 } from 'react-icons/lu'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/ConfirmDialog'
import { CopyButton } from '@/components/CopyButton'
import { DataTable, type Column } from '@/components/DataTable'
import { EmptyState } from '@/components/EmptyState'
import { Field } from '@/components/ops/Field'
import { toastError } from '@/components/ops/toast'
import { TimeAgo } from '@/components/TimeAgo'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { useAPITokens, useCreateAPIToken, useRevokeAPIToken } from '@/lib/api/client'
import type { APIToken, APITokenCreated } from '@/lib/api/types'

/** Expiry presets in days; 0 = never. */
const EXPIRY = [
  { value: '0', label: 'Never' },
  { value: '30', label: '30 days' },
  { value: '90', label: '90 days' },
  { value: '365', label: '365 days' },
]

const expired = (t: APIToken) => t.expires_at !== null && new Date(t.expires_at).getTime() <= Date.now()

/** Admin-only: read-only API tokens for tools such as Grafana (SPEC §10). */
export function APITokensCard() {
  const { data, isPending, error } = useAPITokens()
  const revoke = useRevokeAPIToken()
  const [adding, setAdding] = useState(false)

  const columns: Column<APIToken>[] = [
    { key: 'name', header: 'Name', sortValue: (t) => t.name, cell: (t) => t.name },
    { key: 'prefix', header: 'Token', cell: (t) => <code className="font-mono">{t.prefix}…</code> },
    {
      key: 'status',
      header: 'Status',
      sortValue: (t) => (t.revoked ? 2 : expired(t) ? 1 : 0),
      cell: (t) =>
        t.revoked ? <Badge variant="destructive">revoked</Badge> : expired(t) ? <Badge variant="secondary">expired</Badge> : <Badge>active</Badge>,
    },
    { key: 'by', header: 'Created by', sortValue: (t) => t.created_by_email, cell: (t) => t.created_by_email || '—' },
    { key: 'created', header: 'Created', sortValue: (t) => t.created_at, cell: (t) => <TimeAgo date={t.created_at} /> },
    {
      key: 'used',
      header: 'Last used',
      sortValue: (t) => t.last_used_at ?? '',
      cell: (t) => (t.last_used_at ? <TimeAgo date={t.last_used_at} /> : <span className="text-muted-foreground">never</span>),
    },
    {
      key: 'expires',
      header: 'Expires',
      sortValue: (t) => t.expires_at ?? '9999',
      cell: (t) => (t.expires_at ? <TimeAgo date={t.expires_at} /> : <span className="text-muted-foreground">never</span>),
    },
    {
      key: 'actions',
      header: '',
      align: 'right',
      cell: (t) =>
        !t.revoked && (
          <ConfirmDialog
            title={`Revoke API token "${t.name}"?`}
            description="Anything using it (e.g. a Grafana data source) gets 401 immediately. This cannot be undone."
            confirmLabel="Revoke"
            destructive
            onConfirm={() => revoke.mutateAsync(t.id).then(() => toast.success(`Token "${t.name}" revoked`), toastError)}
          >
            <Button variant="ghost" size="icon" className="size-8 text-destructive" aria-label={`Revoke ${t.name}`}>
              <LuTrash2 />
            </Button>
          </ConfirmDialog>
        ),
    },
  ]

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-2">
        <div className="space-y-1.5">
          <CardTitle className="flex items-center gap-2">
            <LuKeyRound className="size-5" aria-hidden />
            API tokens
          </CardTitle>
          <CardDescription>
            Read-only access for tools such as Grafana: send <code className="font-mono">Authorization: Bearer djt_…</code>. Tokens act as a
            viewer on GET endpoints only; they never work for admin actions or changes.
          </CardDescription>
        </div>
        <Button size="sm" onClick={() => setAdding(true)}>
          <LuPlus />
          New token
        </Button>
      </CardHeader>
      <CardContent>
        <DataTable
          columns={columns}
          rows={data?.items}
          loading={isPending}
          error={error}
          rowKey={(t) => t.id}
          defaultSort={{ key: 'created', desc: true }}
          empty={<EmptyState icon={LuKeyRound} title="No API tokens" description="Create one to read panel data from another tool." />}
        />
      </CardContent>
      {adding && <CreateTokenDialog onClose={() => setAdding(false)} />}
    </Card>
  )
}

function CreateTokenDialog({ onClose }: { onClose: () => void }) {
  const [name, setName] = useState('')
  const [days, setDays] = useState('90')
  const [created, setCreated] = useState<APITokenCreated>()
  const create = useCreateAPIToken()

  const submit = (e: FormEvent) => {
    e.preventDefault()
    create.mutate({ name: name.trim(), expires_in_days: Number(days) || undefined }, { onSuccess: setCreated, onError: toastError })
  }

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-lg">
        {created ? (
          <>
            <DialogHeader>
              <DialogTitle>Token "{created.name}" created</DialogTitle>
              <DialogDescription>Use it as a bearer token on read-only (GET) API endpoints.</DialogDescription>
            </DialogHeader>
            <div className="flex items-start gap-2 rounded-md border bg-muted/50 p-3">
              <code className="min-w-0 flex-1 font-mono text-xs break-all">{created.token}</code>
              <CopyButton value={created.token} />
            </div>
            <p className="flex items-start gap-2 text-sm text-warning">
              <LuTriangleAlert className="mt-0.5 shrink-0" aria-hidden />
              Copy it now: it is shown only once and cannot be recovered. Revoke it and create a new one if it is lost or leaked.
            </p>
            <DialogFooter>
              <Button onClick={onClose}>Done</Button>
            </DialogFooter>
          </>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle>New API token</DialogTitle>
              <DialogDescription>Read-only: grants viewer access to GET endpoints.</DialogDescription>
            </DialogHeader>
            <form onSubmit={submit} className="grid gap-4">
              <Field id="token-name" label="Name" hint="Where it is used, e.g. the Grafana instance.">
                <Input id="token-name" value={name} onChange={(e) => setName(e.target.value)} required maxLength={100} placeholder="grafana" />
              </Field>
              <Field id="token-expiry" label="Expires">
                <Select value={days} onValueChange={setDays}>
                  <SelectTrigger id="token-expiry" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {EXPIRY.map((x) => (
                      <SelectItem key={x.value} value={x.value}>
                        {x.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </Field>
              <DialogFooter>
                <Button type="button" variant="outline" onClick={onClose}>
                  Cancel
                </Button>
                <Button type="submit" disabled={create.isPending || !name.trim()}>
                  {create.isPending ? 'Creating…' : 'Create token'}
                </Button>
              </DialogFooter>
            </form>
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}
