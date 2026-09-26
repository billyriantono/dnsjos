import { useState, type ReactNode } from 'react'
import { LuCircleCheck, LuCircleX, LuLoaderCircle, LuRefreshCw } from 'react-icons/lu'
import { toast } from 'sonner'

import { useAuth } from '@/app/auth'
import { ConfirmDialog } from '@/components/ConfirmDialog'
import { EmptyState } from '@/components/EmptyState'
import { TimeAgo } from '@/components/TimeAgo'
import { toastError } from '@/components/ops/toast'
import { fmtSeries, sortVersions } from '@/components/upgrades/versions'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { useMeta, useNodeCommand, useNodeVersions } from '@/lib/api/client'
import type { CommandRequest, Node, UpgradeResult } from '@/lib/api/types'

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3 py-1.5 text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span className="flex min-w-0 items-center gap-2 text-right font-mono text-xs">{children}</span>
    </div>
  )
}

function LastUpgrade({ r }: { r: UpgradeResult | null }) {
  if (!r) return <p className="text-sm text-muted-foreground">No upgrade has run on this node yet.</p>
  return (
    <div className="flex gap-2 text-sm">
      {r.ok ? <LuCircleCheck className="mt-0.5 size-4 shrink-0 text-success" /> : <LuCircleX className="mt-0.5 size-4 shrink-0 text-destructive" />}
      <div className="min-w-0 space-y-0.5">
        <p>
          {r.kind} <span className="font-mono text-xs">{r.from || '—'}</span> → <span className="font-mono text-xs">{r.to || '—'}</span>{' '}
          <span className="text-muted-foreground">
            {r.ok ? 'succeeded' : 'failed'} <TimeAgo date={r.at} />
          </span>
        </p>
        {r.error && <p className="font-mono text-xs break-all text-destructive">{r.error}</p>}
      </div>
    </div>
  )
}

export function NodeVersionsTab({ node }: { node: Node }) {
  const { isAdmin } = useAuth()
  const q = useNodeVersions(node.id)
  const meta = useMeta()
  const cmd = useNodeCommand()
  const [pick, setPick] = useState<string>()
  const [series, setSeries] = useState<string>()
  const v = q.data

  if (!v) return q.isError ? <EmptyState title="Could not load versions" description={q.error.message} /> : <Skeleton className="h-64" />

  const send = (c: CommandRequest, label: string) =>
    cmd.mutateAsync({ id: node.id, ...c }).then(() => toast.success(`${label} queued`, { description: 'The agent picks it up on its next heartbeat.' }), toastError)

  const busy = v.upgrade_in_progress
  const available = sortVersions(v.available)
  const target = pick && available.includes(pick) ? pick : available.includes(v.candidate) ? v.candidate : available[0]
  const otherSeries = (meta.data?.supported_series ?? []).filter((s) => s !== v.series)
  const newSeries = series && otherSeries.includes(series) ? series : otherSeries[0]

  return (
    <div className="space-y-4">
      {busy && (
        <div className="flex items-center gap-2 rounded-lg border border-info/30 bg-info/10 px-4 py-3 text-sm text-info">
          <LuLoaderCircle className="size-4 animate-spin" /> An upgrade is running on this node. Actions are disabled until it reports back.
        </div>
      )}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>dnsdist</CardTitle>
            <CardDescription>
              Inventory <TimeAgo date={v.inventory_at} /> · refreshed every 6 h
            </CardDescription>
            {isAdmin && (
              <CardAction>
                <Button variant="outline" size="sm" disabled={busy || cmd.isPending} onClick={() => send({ type: 'check_updates' }, 'Update check')}>
                  <LuRefreshCw /> Check for updates
                </Button>
              </CardAction>
            )}
          </CardHeader>
          <CardContent className="divide-y">
            <Row label="Installed">{v.installed || '—'}</Row>
            <Row label="Candidate">
              {v.candidate && v.candidate !== v.installed && (
                <Badge variant="outline" className="border-primary/30 bg-primary/10 font-sans text-primary">
                  update available
                </Badge>
              )}
              {v.candidate || '—'}
            </Row>
            <Row label="Series">{fmtSeries(v.series)}</Row>
            {isAdmin && (
              <div className="flex flex-wrap items-center gap-2 pt-3">
                <Select value={target ?? ''} onValueChange={setPick} disabled={!available.length}>
                  <SelectTrigger className="w-60 font-mono text-xs" aria-label="Target version">
                    <SelectValue placeholder="No versions known yet" />
                  </SelectTrigger>
                  <SelectContent>
                    {available.map((a) => (
                      <SelectItem key={a} value={a} className="font-mono text-xs">
                        {a}
                        {a === v.installed && ' (installed)'}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <ConfirmDialog
                  title={`Upgrade dnsdist on ${node.name}?`}
                  confirmLabel="Upgrade"
                  onConfirm={() => send({ type: 'upgrade_dnsdist', version: target }, 'Upgrade')}
                  description={
                    <>
                      dnsdist goes from <b className="font-mono">{v.installed || '?'}</b> to <b className="font-mono">{target}</b> and restarts once: this node stops
                      answering for a few seconds, so make sure its clients can fail over to another node. Afterwards the agent checks that dnsdist runs, the config
                      validates, a test query resolves and blocking works; if any check fails it downgrades back to {v.installed || 'the previous version'}{' '}
                      automatically.
                    </>
                  }
                >
                  <Button disabled={busy || !target || target === v.installed}>Upgrade</Button>
                </ConfirmDialog>
              </div>
            )}
            {isAdmin && otherSeries.length > 0 && (
              <div className="flex flex-wrap items-center gap-2 pt-3">
                <Select value={newSeries} onValueChange={setSeries}>
                  <SelectTrigger className="w-32" aria-label="Series">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {otherSeries.map((s) => (
                      <SelectItem key={s} value={s}>
                        {fmtSeries(s)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <ConfirmDialog
                  destructive
                  title={`Switch ${node.name} to dnsdist ${fmtSeries(newSeries)}?`}
                  confirmLabel="Switch series"
                  confirmText={node.name}
                  onConfirm={() => send({ type: 'set_dnsdist_series', series: newSeries }, 'Series switch')}
                  description={`Rewrites the PowerDNS apt source and pin on ${node.name} from ${fmtSeries(v.series)} to ${fmtSeries(newSeries)}. dnsdist itself is not touched until you run an upgrade, but from then on only ${fmtSeries(newSeries)} versions are offered. Major series can change behaviour; try it on one node first.`}
                >
                  <Button variant="outline" disabled={busy}>
                    Switch series
                  </Button>
                </ConfirmDialog>
              </div>
            )}
          </CardContent>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Agent</CardTitle>
              <CardDescription>Agent restarts do not touch dnsdist.</CardDescription>
            </CardHeader>
            <CardContent className="divide-y">
              <Row label="Installed">
                {v.agent_outdated && (
                  <Badge variant="outline" className="border-warning/30 bg-warning/10 font-sans text-warning">
                    outdated
                  </Badge>
                )}
                {v.agent_version || '—'}
              </Row>
              <Row label="Panel ships">{v.panel_agent_version || '—'}</Row>
              {isAdmin && (
                <div className="pt-3">
                  <ConfirmDialog
                    title={`Upgrade the agent on ${node.name}?`}
                    confirmLabel="Upgrade agent"
                    onConfirm={() => send({ type: 'upgrade_agent' }, 'Agent upgrade')}
                    description={`The agent downloads ${v.panel_agent_version} from the panel, verifies its checksum, replaces itself and restarts. dnsdist keeps serving throughout.`}
                  >
                    <Button variant={v.agent_outdated ? 'default' : 'outline'} disabled={busy || !v.agent_outdated}>
                      Upgrade agent
                    </Button>
                  </ConfirmDialog>
                </div>
              )}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Last upgrade</CardTitle>
            </CardHeader>
            <CardContent>
              <LastUpgrade r={v.last_upgrade} />
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}
