import type { ReactNode } from 'react'
import { LuTriangleAlert } from 'react-icons/lu'

import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Textarea } from '@/components/ui/textarea'
import type { SpecErrors } from '@/lib/api/profiles'
import { DYN_ACTIONS, type ConfigSpec, type DynAction, type Listen } from '@/lib/api/types'
import { fmtBytes } from '@/lib/format'
import { cn } from '@/lib/utils'
import { TABS, tabOf, useFieldErrors, useReadOnly, type TabId } from './context'
import { ListEditor, NumField, Section, SwitchField, TextField } from './fields'
import { UpstreamsEditor } from './UpstreamsEditor'
import { isCIDR, isHostname, isIPPort } from './validate'

const DYN_HELP: Record<DynAction, string> = {
  truncate: 'answer with TC=1 so real resolvers retry over TCP; spoofed-source floods cannot',
  drop: 'silently drop queries',
  refused: 'answer REFUSED',
}

function Errors({ path }: { path: string }) {
  const errs = useFieldErrors(path)
  return errs.length ? <p className="text-sm text-destructive">{errs.join(' · ')}</p> : null
}

const Grid = ({ children, cols = 3 }: { children: ReactNode; cols?: 2 | 3 | 4 }) => (
  <div className={cn('grid gap-4 sm:grid-cols-2', cols === 3 && 'lg:grid-cols-3', cols === 4 && 'lg:grid-cols-4')}>
    {children}
  </div>
)

/** Structured editor for every ConfigSpec field. Controlled: `value` in, whole new spec out. */
export function ConfigForm({
  value: s,
  onChange,
  errors,
  tab,
  onTabChange,
}: {
  value: ConfigSpec
  onChange: (s: ConfigSpec) => void
  errors: SpecErrors
  tab: TabId
  onTabChange: (t: TabId) => void
}) {
  const ro = useReadOnly()
  const set = <K extends keyof ConfigSpec>(k: K, v: ConfigSpec[K]) => onChange({ ...s, [k]: v })
  const part = <K extends Exclude<keyof ConfigSpec, 'acl'>>(k: K, p: Partial<ConfigSpec[K]>) =>
    set(k, { ...s[k], ...p })
  const listen = <K extends keyof Listen>(k: K, p: Partial<Listen[K]>) =>
    part('listen', { [k]: { ...s.listen[k], ...p } } as Partial<Listen>)
  const errTabs = new Set(Object.keys(errors).map(tabOf))

  const { do53, doh, dot, tls } = s.listen
  const { blocking: b, abuse: a, cgk: g, cache: c, analytics: an, dualstack: ds, speed_check: sc } = s

  return (
    <Tabs value={tab} onValueChange={(t) => onTabChange(t as TabId)} className="gap-4">
      <div className="overflow-x-auto">
        <TabsList className="max-w-full justify-start overflow-x-auto">
          {TABS.map((t) => (
            <TabsTrigger key={t.id} value={t.id} className="gap-1.5">
              {t.label}
              {errTabs.has(t.id) && <span className="size-1.5 rounded-full bg-destructive" aria-label="has errors" />}
            </TabsTrigger>
          ))}
        </TabsList>
      </div>

      <TabsContent value="listen" className="grid gap-4">
        <Errors path="listen" />
        <Section
          title="Do53 (plain DNS)"
          description="UDP + TCP port 53."
          enabled={do53.enabled}
          onEnabledChange={(enabled) => listen('do53', { enabled })}
        >
          <ListEditor
            label="Addresses"
            path="listen.do53.addresses"
            value={do53.addresses}
            onChange={(addresses) => listen('do53', { addresses })}
            validate={isIPPort}
            what="ip:port"
            placeholder="0.0.0.0:53 [::]:53"
          />
          <NumField
            className="max-w-xs"
            label="Listeners per address"
            path="listen.do53.reuse_port_listeners"
            value={do53.reuse_port_listeners}
            onChange={(reuse_port_listeners) => listen('do53', { reuse_port_listeners })}
            min={1}
            max={64}
            help="SO_REUSEPORT sockets per address; raise it on busy many-core nodes."
          />
        </Section>
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          <Section
            title="DoH (DNS over HTTPS)"
            enabled={doh.enabled}
            onEnabledChange={(enabled) => listen('doh', { enabled })}
          >
            <ListEditor
              label="Addresses"
              path="listen.doh.addresses"
              value={doh.addresses}
              onChange={(addresses) => listen('doh', { addresses })}
              validate={isIPPort}
              what="ip:port"
            />
            <TextField
              label="URL path"
              path="listen.doh.path"
              value={doh.path}
              onChange={(path) => listen('doh', { path })}
              placeholder="/dns-query"
            />
          </Section>
          <Section
            title="DoT (DNS over TLS)"
            enabled={dot.enabled}
            onEnabledChange={(enabled) => listen('dot', { enabled })}
          >
            <ListEditor
              label="Addresses"
              path="listen.dot.addresses"
              value={dot.addresses}
              onChange={(addresses) => listen('dot', { addresses })}
              validate={isIPPort}
              what="ip:port"
            />
          </Section>
        </div>
        <Section title="TLS certificate" description="Used by DoH and DoT. Absolute paths on the node; the agent does not issue certificates.">
          <Grid cols={2}>
            <TextField label="Certificate file" path="listen.tls.cert_file" value={tls.cert_file} onChange={(cert_file) => listen('tls', { cert_file })} />
            <TextField label="Key file" path="listen.tls.key_file" value={tls.key_file} onChange={(key_file) => listen('tls', { key_file })} />
          </Grid>
        </Section>
      </TabsContent>

      <TabsContent value="acl">
        <Section
          title="Client ACL"
          description="Only clients in these networks may query. Everything else gets REFUSED — keep the resolver closed to the internet."
        >
          <ListEditor
            label="Allowed networks"
            path="acl"
            value={s.acl}
            onChange={(acl) => set('acl', acl)}
            validate={isCIDR}
            what="CIDR"
            placeholder="103.0.0.0/22 2001:db8::/32 — paste a whole list"
            help="CIDR or single address (treated as /32 or /128). IPv4 and IPv6."
          />
        </Section>
      </TabsContent>

      <TabsContent value="upstreams">
        <UpstreamsEditor value={s.upstreams} onChange={(u) => set('upstreams', u)} />
      </TabsContent>

      <TabsContent value="cache">
        <Section
          title="Packet cache"
          description="Answers are cached per node; hits never reach the upstreams."
          enabled={c.enabled}
          onEnabledChange={(enabled) => part('cache', { enabled })}
        >
          <Grid cols={4}>
            <NumField label="Max entries" path="cache.max_entries" value={c.max_entries} onChange={(max_entries) => part('cache', { max_entries })} min={1} help="≈ 500 bytes of RAM each." />
            <NumField label="Min TTL" path="cache.min_ttl" value={c.min_ttl} onChange={(min_ttl) => part('cache', { min_ttl })} min={0} unit="s" help="Raise short TTLs to at least this." />
            <NumField label="Max TTL" path="cache.max_ttl" value={c.max_ttl} onChange={(max_ttl) => part('cache', { max_ttl })} min={0} unit="s" help="Cap long TTLs." />
            <NumField label="Stale TTL" path="cache.stale_ttl" value={c.stale_ttl} onChange={(stale_ttl) => part('cache', { stale_ttl })} min={0} unit="s" help="When every upstream is down, keep answering from expired cache entries for this long (stale answers carry a 60 s TTL). 0 = off." />
          </Grid>
        </Section>
      </TabsContent>

      <TabsContent value="blocking" className="grid gap-4">
        <Section
          title="TrustPositif blocking"
          description="Queries for names in the blocklist CDB are answered locally with the blockpage."
          enabled={b.enabled}
          onEnabledChange={(enabled) => part('blocking', { enabled })}
        >
          <Grid cols={2}>
            <TextField label="Blockpage IPv4 (A)" path="blocking.blockpage_ipv4" value={b.blockpage_ipv4} onChange={(blockpage_ipv4) => part('blocking', { blockpage_ipv4 })} placeholder="192.0.2.10" />
            <TextField label="Blockpage IPv6 (AAAA)" path="blocking.blockpage_ipv6" value={b.blockpage_ipv6} onChange={(blockpage_ipv6) => part('blocking', { blockpage_ipv6 })} />
          </Grid>
          <TextField label="TXT answer" path="blocking.txt" value={b.txt} onChange={(txt) => part('blocking', { txt })} mono={false} help={`${b.txt.length}/255 characters. Returned for TXT lookups of blocked names.`} />
          <Grid cols={2}>
            <TextField label="SOA answer" path="blocking.soa" value={b.soa} onChange={(soa) => part('blocking', { soa })} help="mname rname serial refresh retry expire minimum" />
            <TextField label="NS answer" path="blocking.ns" value={b.ns} onChange={(ns) => part('blocking', { ns })} />
          </Grid>
          <p className="text-xs text-muted-foreground">Every other query type for a blocked name (HTTPS, SVCB, MX…) gets an empty NOERROR answer.</p>
          <Grid cols={2}>
            <SwitchField
              label="Block response IPs"
              help="Also rewrite A answers whose IP is on the TrustPositif IP list to the blockpage."
              checked={b.block_response_ips}
              onChange={(block_response_ips) => part('blocking', { block_response_ips })}
            />
            <SwitchField
              label="Log blocked queries"
              help="Stream blocked names to the agent (dnstap) for the Ministry reports."
              checked={b.log_blocked}
              onChange={(log_blocked) => part('blocking', { log_blocked })}
            />
          </Grid>
        </Section>
      </TabsContent>

      <TabsContent value="abuse" className="grid gap-4">
        <Section
          title="Abuse protection"
          description="Per-client rate limits and dynamic blocks against floods and random-subdomain attacks."
          enabled={a.enabled}
          onEnabledChange={(enabled) => part('abuse', { enabled })}
        >
          <div className="grid gap-2">
            <h3 className="text-sm font-medium">Hard cap</h3>
            <Grid cols={2}>
              <NumField label="Per-client rate" path="abuse.per_client_qps" value={a.per_client_qps} onChange={(per_client_qps) => part('abuse', { per_client_qps })} min={1} unit="qps" help="Queries above this rate from one IP are dropped (IPv4 /32, IPv6 /64)." />
              <NumField label="Burst" path="abuse.per_client_burst" value={a.per_client_burst} onChange={(per_client_burst) => part('abuse', { per_client_burst })} min={a.per_client_qps} unit="queries" help="Short bursts allowed above the rate; must be ≥ the rate." />
            </Grid>
          </div>
          <div className="grid gap-2">
            <h3 className="text-sm font-medium">Dynamic blocks</h3>
            <p className="text-xs text-muted-foreground">
              Measured over the window; a client over any threshold is blocked for the block time. A warning is raised at half
              the rate.
            </p>
            <Grid>
              <NumField label="Query rate" path="abuse.dyn_query_rate" value={a.dyn_query_rate} onChange={(dyn_query_rate) => part('abuse', { dyn_query_rate })} min={1} unit="qps" />
              <NumField label="NXDOMAIN rate" path="abuse.dyn_nxdomain_rate" value={a.dyn_nxdomain_rate} onChange={(dyn_nxdomain_rate) => part('abuse', { dyn_nxdomain_rate })} min={1} unit="/s" help="Catches random-subdomain (water-torture) attacks." />
              <NumField label="SERVFAIL rate" path="abuse.dyn_servfail_rate" value={a.dyn_servfail_rate} onChange={(dyn_servfail_rate) => part('abuse', { dyn_servfail_rate })} min={1} unit="/s" />
              <NumField label="Window" path="abuse.dyn_window_s" value={a.dyn_window_s} onChange={(dyn_window_s) => part('abuse', { dyn_window_s })} min={1} max={3600} unit="s" />
              <NumField label="Block time" path="abuse.dyn_block_s" value={a.dyn_block_s} onChange={(dyn_block_s) => part('abuse', { dyn_block_s })} min={1} max={86400} unit="s" />
              <div className="grid content-start gap-1.5">
                <Label htmlFor="abuse-dyn-action">Action</Label>
                <Select value={a.dyn_action} onValueChange={(v) => part('abuse', { dyn_action: v as DynAction })} disabled={ro}>
                  <SelectTrigger id="abuse-dyn-action" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {DYN_ACTIONS.map((d) => (
                      <SelectItem key={d} value={d}>
                        {d}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">{DYN_HELP[a.dyn_action]}</p>
                <Errors path="abuse.dyn_action" />
              </div>
            </Grid>
          </div>
          <ListEditor
            label="Trusted networks"
            path="abuse.trusted"
            value={a.trusted}
            onChange={(trusted) => part('abuse', { trusted })}
            validate={isCIDR}
            what="CIDR"
            help="Never rate-limited or blocked (monitoring, CGNAT gateways, your own resolvers)."
          />
        </Section>
      </TabsContent>

      <TabsContent value="cgk" className="grid gap-4">
        <Section
          title="CGK redirection"
          description="Rewrites Cloudflare answers served from the congested CGK (Jakarta) colo to measured non-CGK aliases."
          enabled={g.enabled}
          onEnabledChange={(enabled) => part('cgk', { enabled })}
        >
          <Grid cols={2}>
            <ListEditor label="Rewrite pools" path="cgk.rewrite_pools" value={g.rewrite_pools} onChange={(rewrite_pools) => part('cgk', { rewrite_pools })} validate={isCIDR} what="CIDR" help="Candidate ranges; the agent measures which ones land on CGK and rewrites those." />
            <ListEditor label="Alias pools" path="cgk.alias_pools" value={g.alias_pools} onChange={(alias_pools) => part('cgk', { alias_pools })} validate={isCIDR} what="CIDR" help="Ranges probed for aliases that are served outside CGK." />
            <ListEditor label="Test sites" path="cgk.test_sites" value={g.test_sites} onChange={(test_sites) => part('cgk', { test_sites })} validate={isHostname} what="domain" help="Cloudflare-hosted sites used to check that an alias really works." />
            <ListEditor label="Exclude" path="cgk.exclude" value={g.exclude} onChange={(exclude) => part('cgk', { exclude })} validate={isHostname} what="domain" help="Names (and their subdomains) never rewritten — tunnels, ACME, mail." />
          </Grid>
          <Grid>
            <NumField label="Aliases wanted" path="cgk.aliases_wanted" value={g.aliases_wanted} onChange={(aliases_wanted) => part('cgk', { aliases_wanted })} min={1} max={256} help="How many working aliases the prober keeps." />
            <NumField label="Min OK test sites" path="cgk.min_ok" value={g.min_ok} onChange={(min_ok) => part('cgk', { min_ok })} min={1} max={Math.max(1, g.test_sites.length)} help={`An alias must serve at least this many of the ${g.test_sites.length} test sites.`} />
            <NumField label="Refresh interval" path="cgk.refresh_interval_h" value={g.refresh_interval_h} onChange={(refresh_interval_h) => part('cgk', { refresh_interval_h })} min={1} max={168} unit="hours" />
          </Grid>
        </Section>
      </TabsContent>

      <TabsContent value="speed_check" className="grid gap-4">
        <Section title="Speed check" description="smartdns speed-check-mode: how the agent measures addresses, for fastest-IP answers and dual-stack selection.">
          <TextField
            className="max-w-md"
            label="Mode"
            path="speed_check.mode"
            value={sc.mode}
            onChange={(mode) => part('speed_check', { mode })}
            placeholder="ping,tcp:80,tcp:443"
            help="ping (ICMP) or tcp:<port>, in order. The next method starts 100 ms later if no address answered yet; the fastest answer wins, slower than 950 ms counts as no answer. none = no speed test."
          />
        </Section>
        <Section
          title="Fastest-IP answers"
          description="smartdns' answer after its speed test (the one it caches in every response-mode). Every 10 minutes the agent speed-checks every address of the busiest names with several addresses. Their A/AAAA answers then list the fastest address first, then only the ones nearly as fast (< 5 ms slower, within 10 % + 0.5 ms, or < 10 ms); addresses that did not answer are dropped and a CNAME chain becomes one CNAME. dnsdist cannot hold a query while it measures, so the first answers of a new name pass through unchanged, like smartdns' fastest-response."
          enabled={sc.fastest_ip}
          onEnabledChange={(fastest_ip) => part('speed_check', { fastest_ip })}
        >
          <Grid>
            <NumField
              label="Max addresses"
              path="speed_check.max_reply_ip_num"
              value={sc.max_reply_ip_num}
              onChange={(max_reply_ip_num) => part('speed_check', { max_reply_ip_num })}
              min={0}
              max={64}
              help="max-reply-ip-num: at most this many addresses per answer. 0 = 8."
            />
          </Grid>
          <ListEditor
            label="Exclude"
            path="speed_check.exclude"
            value={sc.exclude}
            onChange={(exclude) => part('speed_check', { exclude })}
            validate={isHostname}
            what="domain"
            help="Names (and their subdomains) whose answers are never reordered (domain-rules -speed-check-mode none)."
          />
        </Section>
      </TabsContent>

      <TabsContent value="dualstack" className="grid gap-4">
        <Section
          title="Dual-stack IP selection"
          description="smartdns dualstack-ip-selection. Every 10 minutes the agent speed-checks the names clients get AAAA answers for over IPv4 and IPv6. When IPv4 is faster by at least the threshold, or IPv6 does not answer, AAAA queries for the name get NODATA (with an SOA, like smartdns) so clients use IPv4. Measured with the Speed check tab's mode. Only enable it on nodes whose IPv6 path is the same as their clients' (the node measures on their behalf)."
          enabled={ds.enabled}
          onEnabledChange={(enabled) => part('dualstack', { enabled })}
        >
          <Grid>
            <NumField
              label="Threshold"
              path="dualstack.threshold_ms"
              value={ds.threshold_ms}
              onChange={(threshold_ms) => part('dualstack', { threshold_ms })}
              min={0}
              max={1000}
              unit="ms"
              help="dualstack-ip-selection-threshold: the faster family must win by at least this much. 0 = 10 ms."
            />
            <SwitchField
              label="Allow force AAAA"
              help="dualstack-ip-allow-force-AAAA: also answer A queries NODATA when IPv6 is faster."
              checked={ds.allow_force_aaaa}
              onChange={(allow_force_aaaa) => part('dualstack', { allow_force_aaaa })}
            />
          </Grid>
          <ListEditor
            label="Exclude"
            path="dualstack.exclude"
            value={ds.exclude}
            onChange={(exclude) => part('dualstack', { exclude })}
            validate={isHostname}
            what="domain"
            help="Names (and their subdomains) whose answers are never dropped (domain-rules -dualstack-ip-selection no)."
          />
        </Section>
      </TabsContent>

      <TabsContent value="analytics" className="grid gap-4">
        <Section
          title="Traffic analytics"
          description="Counts every answered query (cache hits included) into daily top-domain, NXDOMAIN, SERVFAIL, query-type and response-code reports. No client addresses are collected."
          enabled={an.enabled}
          onEnabledChange={(enabled) => part('analytics', { enabled })}
        >
          <Grid>
            <NumField
              label="Sample rate"
              path="analytics.sample_rate"
              value={an.sample_rate}
              onChange={(sample_rate) => part('analytics', { sample_rate })}
              min={1}
              max={1000}
              unit="1 in N"
              help={
                an.sample_rate > 1
                  ? `Logs 1 in ${an.sample_rate} answers and multiplies counts by ${an.sample_rate}: less CPU on busy nodes, but all counts become approximate estimates.`
                  : 'Every answer is logged; counts are exact (except the long tail of the top lists). Raise on very busy nodes to save CPU — counts then become approximate.'
              }
            />
            <NumField
              label="Top-K"
              path="analytics.top_k"
              value={an.top_k}
              onChange={(top_k) => part('analytics', { top_k })}
              min={100}
              max={50000}
              unit="names"
              help="Names tracked per list and day on the node. Larger = more accurate long tail, more agent memory."
            />
            <TextField label="Stream address" path="analytics.stream_addr" value={an.stream_addr} onChange={(stream_addr) => part('analytics', { stream_addr })} placeholder="127.0.0.1:6001" help="dnstap listener of the agent. Keep it on loopback." />
          </Grid>
        </Section>
      </TabsContent>

      <TabsContent value="tuning" className="grid gap-4">
        <Section title="Tuning">
          <Grid cols={2}>
            <NumField label="UDP socket buffer" path="tuning.udp_buffer_bytes" value={s.tuning.udp_buffer_bytes} onChange={(udp_buffer_bytes) => part('tuning', { udp_buffer_bytes })} min={0} unit="bytes" help={`${fmtBytes(s.tuning.udp_buffer_bytes)} receive + send per socket. 0 = kernel default.`} />
            <NumField label="TCP workers" path="tuning.tcp_workers" value={s.tuning.tcp_workers} onChange={(tcp_workers) => part('tuning', { tcp_workers })} min={0} max={1024} help="0 = dnsdist default." />
          </Grid>
        </Section>
        <Section title="Built-in webserver" description="Local API and Prometheus endpoint the agent scrapes. Keep it on loopback.">
          <Grid cols={2}>
            <TextField label="Listen" path="webserver.listen" value={s.webserver.listen} onChange={(v) => part('webserver', { listen: v })} placeholder="127.0.0.1:8083" />
            <ListEditor label="Prometheus ACL" path="webserver.prometheus_acl" value={s.webserver.prometheus_acl} onChange={(prometheus_acl) => part('webserver', { prometheus_acl })} validate={isCIDR} what="CIDR" />
          </Grid>
        </Section>
        <Section title="Extra Lua" description="Appended verbatim at the end of dnsdist.conf.">
          <div className="flex gap-2 rounded-md border border-warning/40 bg-warning/10 p-3 text-sm">
            <LuTriangleAlert className="mt-0.5 size-4 shrink-0 text-warning" />
            <p>
              Not validated by the panel. A syntax error makes dnsdist refuse the config; the agent then rolls back to the
              last good version and reports the error on the node page. Preview before publishing.
            </p>
          </div>
          <Textarea
            aria-label="Extra Lua"
            value={s.tuning.extra_lua}
            readOnly={ro}
            onChange={(e) => part('tuning', { extra_lua: e.target.value })}
            placeholder={'-- e.g.\naddAction(QNameRule("example.test."), RCodeAction(DNSRCode.REFUSED))'}
            spellCheck={false}
            className="min-h-48 font-mono text-xs"
          />
          <Errors path="tuning.extra_lua" />
        </Section>
      </TabsContent>
    </Tabs>
  )
}
