import { useState, type FormEvent } from 'react'
import { LuPlus, LuShieldCheck, LuTrash2 } from 'react-icons/lu'
import { toast } from 'sonner'

import { RequireAdmin, useAuth } from '@/app/auth'
import { ConfirmDialog } from '@/components/ConfirmDialog'
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
import { useAddAllow, useAllowlist, useDeleteAllow } from '@/lib/api/client'
import type { AllowEntry, AllowKind } from '@/lib/api/types'

const KIND_LABEL: Record<AllowKind, string> = { domain: 'Domain', ip: 'IP / CIDR' }

/** Expiry presets in hours; 0 = never, -1 = custom date. */
const EXPIRY = [
  { value: '0', label: 'Never', hours: 0 },
  { value: '24', label: '24 hours', hours: 24 },
  { value: '168', label: '7 days', hours: 168 },
  { value: '720', label: '30 days', hours: 720 },
  { value: 'custom', label: 'Custom…', hours: -1 },
] as const

export function AllowlistCard() {
  const { isAdmin } = useAuth()
  const { data, isPending, error } = useAllowlist()
  const remove = useDeleteAllow()
  const [adding, setAdding] = useState(false)

  const columns: Column<AllowEntry>[] = [
    { key: 'kind', header: 'Kind', sortValue: (a) => a.kind, cell: (a) => <Badge variant="secondary">{KIND_LABEL[a.kind]}</Badge> },
    { key: 'value', header: 'Value', sortValue: (a) => a.value, cell: (a) => <code className="font-mono break-all">{a.value}</code> },
    {
      key: 'reason',
      header: 'Reason',
      className: 'max-w-72',
      cell: (a) => (
        <span className="block truncate" title={a.reason}>
          {a.reason || '—'}
        </span>
      ),
    },
    { key: 'by', header: 'Added by', sortValue: (a) => a.created_by_email, cell: (a) => a.created_by_email || '—' },
    { key: 'created', header: 'Added', sortValue: (a) => a.created_at, cell: (a) => <TimeAgo date={a.created_at} /> },
    {
      key: 'expires',
      header: 'Expires',
      sortValue: (a) => a.expires_at ?? '9999',
      cell: (a) => (a.expires_at ? <TimeAgo date={a.expires_at} /> : <span className="text-muted-foreground">never</span>),
    },
  ]
  if (isAdmin)
    columns.push({
      key: 'actions',
      header: '',
      align: 'right',
      cell: (a) => (
        <ConfirmDialog
          title={`Remove ${a.value} from the allowlist?`}
          description="Nodes block it again within ~15 s if it is on the blocklist."
          confirmLabel="Remove"
          destructive
          onConfirm={() => remove.mutateAsync(a.id).then(() => toast.success(`${a.value} removed from the allowlist`), toastError)}
        >
          <Button variant="ghost" size="icon" className="size-8 text-destructive" aria-label={`Remove ${a.value}`}>
            <LuTrash2 />
          </Button>
        </ConfirmDialog>
      ),
    })

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-2">
        <div className="space-y-1.5">
          <CardTitle className="flex items-center gap-2">
            <LuShieldCheck className="size-5 text-success" aria-hidden />
            Allowlist (emergency unblock)
          </CardTitle>
          <CardDescription>
            For Komdigi false positives such as CDN domains or IPs that take other sites down. Checked before the blocklist on every
            node and effective within ~15 s without a restart; domains (and their subdomains) are also removed from the next build.
          </CardDescription>
        </div>
        <RequireAdmin>
          <Button size="sm" onClick={() => setAdding(true)}>
            <LuPlus />
            Allow
          </Button>
        </RequireAdmin>
      </CardHeader>
      <CardContent>
        <DataTable
          columns={columns}
          rows={data?.items}
          loading={isPending}
          error={error}
          rowKey={(a) => a.id}
          defaultSort={{ key: 'created', desc: true }}
          empty={<EmptyState icon={LuShieldCheck} title="Nothing allowed" description="Every blocklist entry is enforced." />}
        />
      </CardContent>
      {adding && <AllowDialog onClose={() => setAdding(false)} />}
    </Card>
  )
}

/** Add-to-allowlist dialog; `initial` prefills it from a lookup result. */
export function AllowDialog({ initial, onClose }: { initial?: { kind: AllowKind; value: string }; onClose: () => void }) {
  const [kind, setKind] = useState<AllowKind>(initial?.kind ?? 'domain')
  const [value, setValue] = useState(initial?.value ?? '')
  const [reason, setReason] = useState('')
  const [expiry, setExpiry] = useState<string>('0')
  const [custom, setCustom] = useState('')
  const add = useAddAllow()

  const submit = (e: FormEvent) => {
    e.preventDefault()
    const hours = EXPIRY.find((x) => x.value === expiry)?.hours ?? 0
    if (hours < 0 && !(new Date(custom).getTime() > Date.now())) return void toast.error('The expiry must be in the future')
    const expires_at =
      hours > 0 ? new Date(Date.now() + hours * 3_600_000).toISOString() : hours < 0 ? new Date(custom).toISOString() : undefined
    add.mutate(
      { kind, value: value.trim().toLowerCase(), reason: reason.trim(), expires_at },
      {
        onSuccess: (a) => {
          toast.success(`${a.value} allowed; nodes pick it up within ~15 s`)
          onClose()
        },
        onError: toastError,
      },
    )
  }

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Allow a {kind === 'ip' ? 'IP or CIDR' : 'domain'}</DialogTitle>
          <DialogDescription>
            {kind === 'ip'
              ? 'Answers containing this address are no longer rewritten to the block page.'
              : 'The domain and all its subdomains are never blocked, even if listed.'}
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="grid gap-4">
          <div className="grid gap-4 sm:grid-cols-[10rem_1fr]">
            <Field id="allow-kind" label="Kind">
              <Select value={kind} onValueChange={(v) => setKind(v as AllowKind)}>
                <SelectTrigger id="allow-kind" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {Object.entries(KIND_LABEL).map(([k, label]) => (
                    <SelectItem key={k} value={k}>
                      {label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
            <Field id="allow-value" label={kind === 'ip' ? 'Address or CIDR' : 'Domain'}>
              <Input
                id="allow-value"
                value={value}
                onChange={(e) => setValue(e.target.value)}
                required
                autoComplete="off"
                spellCheck={false}
                className="font-mono"
                placeholder={kind === 'ip' ? '203.0.113.7 or 2001:db8::/32' : 'cdn.example.com'}
              />
            </Field>
          </div>
          <Field id="allow-reason" label="Reason" hint="Recorded in the audit log, e.g. the ticket or the sites affected.">
            <Input id="allow-reason" value={reason} onChange={(e) => setReason(e.target.value)} required placeholder="Shared CDN listed by mistake" />
          </Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field id="allow-expiry" label="Expires">
              <Select value={expiry} onValueChange={setExpiry}>
                <SelectTrigger id="allow-expiry" className="w-full">
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
            {expiry === 'custom' && (
              <Field id="allow-expiry-at" label="Expires at" hint="Local time.">
                <Input
                  id="allow-expiry-at"
                  type="datetime-local"
                  required
                  value={custom}
                  onChange={(e) => setCustom(e.target.value)}
                />
              </Field>
            )}
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={add.isPending || !value.trim() || !reason.trim() || (expiry === 'custom' && !custom)}>
              {add.isPending ? 'Allowing…' : 'Allow'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
