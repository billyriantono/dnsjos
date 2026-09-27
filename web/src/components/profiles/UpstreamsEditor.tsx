import { LuPlus, LuTrash2 } from 'react-icons/lu'

import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Slider } from '@/components/ui/slider'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { POLICY_INFO } from '@/lib/api/profiles'
import { POLICIES, type ServerPolicy, type Upstream, type Upstreams } from '@/lib/api/types'
import { cn } from '@/lib/utils'
import { useFieldErrors, useListErrors, useReadOnly } from './context'
import { NumField, Section } from './fields'
import { isIPPort } from './validate'

const color = (i: number) => `var(--chart-${(i % 5) + 1})`
const pct = (n: number) => `${(n * 100).toFixed(n > 0 && n < 0.1 ? 1 : 0)}%`

function Cell({ path, className, children }: { path: string; className?: string; children: React.ReactNode }) {
  const errs = useFieldErrors(path)
  return (
    <TableCell className={cn('align-top', className)}>
      {children}
      {errs.length > 0 && <p className="mt-1 text-xs whitespace-normal text-destructive">{errs.join(' · ')}</p>}
    </TableCell>
  )
}

export function UpstreamsEditor({ value, onChange }: { value: Upstreams; onChange: (v: Upstreams) => void }) {
  const ro = useReadOnly()
  const listErrs = useListErrors('upstreams.servers').get(-1) ?? []
  const policyErrs = useFieldErrors('upstreams.policy')
  const servers = value.servers
  const info = POLICY_INFO[value.policy] ?? { label: value.policy, help: '', weighted: true }
  const total = servers.reduce((s, u) => s + Math.max(0, u.weight || 0), 0)
  const share = (u: Upstream) => (total > 0 ? Math.max(0, u.weight || 0) / total : 0)

  const setServers = (s: Upstream[]) => onChange({ ...value, servers: s })
  const patch = (i: number, p: Partial<Upstream>) => setServers(servers.map((u, j) => (j === i ? { ...u, ...p } : u)))
  const addServer = () =>
    setServers([...servers, { name: '', address: '', weight: 10, order: 1, sockets: 4 }])

  return (
    <div className="grid gap-4">
      <Section title="Load-balancing policy" description="How dnsdist picks an upstream for each cache miss.">
        <div className="grid grid-cols-1 gap-4 md:grid-cols-[minmax(0,18rem)_1fr]">
          <div className="grid content-start gap-1.5">
            <Label htmlFor="upstream-policy">Policy</Label>
            <Select value={value.policy} onValueChange={(p) => onChange({ ...value, policy: p as ServerPolicy })} disabled={ro}>
              <SelectTrigger id="upstream-policy" className="w-full" aria-invalid={policyErrs.length > 0 || undefined}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {POLICIES.map((p) => (
                  <SelectItem key={p} value={p}>
                    <span className="font-mono text-xs">{p}</span>
                    <span className="text-muted-foreground">· {POLICY_INFO[p].label}</span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {policyErrs.length > 0 && <p className="text-xs text-destructive">{policyErrs.join(' · ')}</p>}
          </div>
          <dl className="grid gap-1.5 rounded-md border bg-muted/30 p-3 text-xs">
            {POLICIES.map((p) => (
              <div key={p} className={cn('grid grid-cols-[8.5rem_1fr] gap-2', p !== value.policy && 'opacity-55')}>
                <dt className={cn('font-mono', p === value.policy && 'font-semibold text-foreground')}>{p}</dt>
                <dd className="text-muted-foreground">{POLICY_INFO[p].help}</dd>
              </div>
            ))}
          </dl>
        </div>
        <NumField
          className="max-w-xs"
          label="Health-check interval"
          path="upstreams.health_check_interval_s"
          value={value.health_check_interval_s}
          onChange={(v) => onChange({ ...value, health_check_interval_s: v })}
          min={1}
          max={3600}
          unit="seconds"
          help="How often each upstream is probed; a down upstream gets no traffic."
        />
        {value.policy === 'whashedLatency' && (
          <NumField
            className="max-w-xs"
            label="Latency floor"
            path="upstreams.latency_floor_ms"
            value={value.latency_floor_ms ?? 0}
            onChange={(v) => onChange({ ...value, latency_floor_ms: v })}
            min={0}
            max={10000}
            unit="ms"
            help="Upstreams answering faster than this count as equally fast, so jitter does not move names around. 0 = 20 ms."
          />
        )}
      </Section>

      <Section
        title="Upstream servers"
        description={
          info.weighted
            ? 'Traffic share follows the weights below.'
            : `${info.label} ignores weights — the share bar shows what weighted policies would do.`
        }
      >
        {servers.length > 0 && (
          <div className="grid gap-2">
            <div className={cn('flex h-3 overflow-hidden rounded-full bg-muted', !info.weighted && 'opacity-40')}>
              {servers.map((u, i) => (
                <div
                  key={i}
                  className="h-full transition-[width] duration-300"
                  style={{ width: pct(share(u)), background: color(i) }}
                  title={`${u.name || u.address}: ${pct(share(u))}`}
                />
              ))}
            </div>
            <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
              {servers.map((u, i) => (
                <span key={i} className="inline-flex items-center gap-1.5">
                  <span className="size-2 rounded-full" style={{ background: color(i) }} />
                  {u.name || u.address || `#${i + 1}`} <span className="tabular text-foreground">{pct(share(u))}</span>
                </span>
              ))}
            </div>
          </div>
        )}

        <div className="overflow-x-auto rounded-md border">
          <Table>
            <TableHeader className="bg-muted/40">
              <TableRow className="hover:bg-transparent">
                <TableHead className="w-36">Name</TableHead>
                <TableHead className="w-48">Address</TableHead>
                <TableHead className="min-w-36">Weight</TableHead>
                <TableHead className="w-20 text-right">Share</TableHead>
                <TableHead className="w-24">Order</TableHead>
                <TableHead className="w-24">Sockets</TableHead>
                {!ro && (
                  <TableHead className="w-10">
                    <span className="sr-only">Remove</span>
                  </TableHead>
                )}
              </TableRow>
            </TableHeader>
            <TableBody>
              {servers.map((u, i) => {
                const p = `upstreams.servers[${i}]`
                return (
                  <TableRow key={i} className="hover:bg-transparent">
                    <Cell path={`${p}.name`}>
                      <div className="flex items-center gap-2">
                        <span className="size-2 shrink-0 rounded-full" style={{ background: color(i) }} />
                        <Input
                          value={u.name}
                          placeholder="optional"
                          readOnly={ro}
                          aria-label="Name"
                          onChange={(e) => patch(i, { name: e.target.value })}
                          className="h-8 min-w-24 font-mono text-sm"
                        />
                      </div>
                    </Cell>
                    <Cell path={`${p}.address`}>
                      <Input
                        value={u.address}
                        placeholder="1.1.1.1:53"
                        readOnly={ro}
                        aria-label="Address"
                        aria-invalid={(u.address !== '' && !isIPPort(u.address)) || undefined}
                        onChange={(e) => patch(i, { address: e.target.value.trim() })}
                        className="h-8 min-w-44 font-mono text-sm"
                      />
                    </Cell>
                    <Cell path={`${p}.weight`}>
                      <div className="flex min-w-36 items-center gap-2">
                        <Slider
                          value={[u.weight]}
                          min={1}
                          max={Math.max(100, u.weight)}
                          disabled={ro}
                          aria-label={`Weight of ${u.name || u.address || `upstream ${i + 1}`}`}
                          onValueChange={([w]) => patch(i, { weight: w })}
                        />
                        <Input
                          type="number"
                          min={1}
                          max={1000}
                          value={u.weight}
                          readOnly={ro}
                          aria-label="Weight value"
                          onChange={(e) => patch(i, { weight: Math.trunc(Number(e.target.value)) || 0 })}
                          className="h-8 w-16 shrink-0 tabular"
                        />
                      </div>
                    </Cell>
                    <TableCell className="text-right align-top">
                      <span className={cn('tabular font-medium leading-8', !info.weighted && 'text-muted-foreground')}>
                        {pct(share(u))}
                      </span>
                    </TableCell>
                    <Cell path={`${p}.order`}>
                      <Input
                        type="number"
                        min={1}
                        max={1000}
                        value={u.order}
                        readOnly={ro}
                        aria-label="Order"
                        onChange={(e) => patch(i, { order: Math.trunc(Number(e.target.value)) || 0 })}
                        className="h-8 min-w-14 tabular"
                      />
                    </Cell>
                    <Cell path={`${p}.sockets`}>
                      <Input
                        type="number"
                        min={1}
                        max={64}
                        value={u.sockets}
                        readOnly={ro}
                        aria-label="Sockets"
                        onChange={(e) => patch(i, { sockets: Math.trunc(Number(e.target.value)) || 0 })}
                        className="h-8 min-w-14 tabular"
                      />
                    </Cell>
                    {!ro && (
                      <TableCell className="align-top">
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          className="size-8 text-muted-foreground hover:text-destructive"
                          aria-label={`Remove ${u.name || u.address}`}
                          onClick={() => setServers(servers.filter((_, j) => j !== i))}
                        >
                          <LuTrash2 />
                        </Button>
                      </TableCell>
                    )}
                  </TableRow>
                )
              })}
              {servers.length === 0 && (
                <TableRow className="hover:bg-transparent">
                  <TableCell colSpan={7} className="py-8 text-center text-sm text-muted-foreground">
                    No upstreams — dnsdist needs at least one.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
        {listErrs.length > 0 && <p className="text-xs text-destructive">{listErrs.join(' · ')}</p>}
        <p className="text-xs text-muted-foreground">
          Order: lower is preferred by <span className="font-mono">firstAvailable</span> and as a tie-breaker by{' '}
          <span className="font-mono">leastOutstanding</span>. Sockets: UDP sockets per upstream (more spreads load across
          CPU cores).
        </p>
        {!ro && (
          <Button type="button" variant="outline" className="w-fit" onClick={addServer}>
            <LuPlus /> Add upstream
          </Button>
        )}
      </Section>
    </div>
  )
}
