// Profile-editor helpers (profiles slice). defaultSpec mirrors api.DefaultConfigSpec() (SPEC §12);
// it is only the starting point for a profile that has no versions yet.
import type { ConfigSpec, ServerPolicy } from './types'

const up = (address: string, name: string, weight: number) => ({ address, name, weight, order: 1, sockets: 4 })

export const defaultSpec = (): ConfigSpec => ({
  listen: {
    do53: { enabled: true, addresses: ['0.0.0.0:53', '[::]:53'], reuse_port_listeners: 1 },
    doh: { enabled: false, addresses: ['0.0.0.0:443', '[::]:443'], path: '/dns-query' },
    dot: { enabled: false, addresses: ['0.0.0.0:853', '[::]:853'] },
    tls: { cert_file: '/etc/dnsdist/tls/cert.pem', key_file: '/etc/dnsdist/tls/key.pem' },
  },
  acl: [
    '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
    '192.168.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10',
  ],
  upstreams: {
    policy: 'whashed',
    servers: [
      up('1.1.1.1:53', 'cloudflare1', 30),
      up('1.0.0.1:53', 'cloudflare2', 30),
      up('8.8.8.8:53', 'google1', 20),
      up('8.8.4.4:53', 'google2', 20),
    ],
    health_check_interval_s: 1,
  },
  cache: { enabled: true, max_entries: 500000, min_ttl: 0, max_ttl: 86400, stale_ttl: 60 },
  blocking: {
    enabled: true,
    blockpage_ipv4: '192.0.2.10',
    blockpage_ipv6: '2001:db8::10',
    txt: 'BLOCKED. UU No 19, pasal 40 (2a dan 2b). Permen Kominfo No 5 2020',
    soa: 'blocked.invalid. nobody.blocked.invalid. 1 3600 1200 604800 10800',
    ns: 'ns.blocked.invalid',
    block_response_ips: true,
    log_blocked: true,
  },
  abuse: {
    enabled: true,
    per_client_qps: 50,
    per_client_burst: 250,
    dyn_query_rate: 40,
    dyn_nxdomain_rate: 15,
    dyn_servfail_rate: 15,
    dyn_window_s: 10,
    dyn_block_s: 300,
    dyn_action: 'truncate',
    trusted: ['127.0.0.0/8', '::1/128'],
  },
  cgk: {
    enabled: true,
    rewrite_pools: [
      '104.20.0.0/16', '104.21.0.0/16', '104.24.0.0/16', '104.25.0.0/16',
      '104.26.0.0/16', '104.27.0.0/16', '172.66.0.0/16', '172.67.0.0/16', '188.114.96.0/20',
    ],
    alias_pools: ['104.16.0.0/16', '104.17.0.0/16', '104.18.0.0/16', '104.19.0.0/16', '172.64.0.0/16'],
    test_sites: ['kincir.com', 'suara.com', 'jagoanhosting.com', 'dewaweb.com'],
    exclude: [
      'argotunnel.com', 'cftunnel.com', 'api.cloudflare.com', 'cloudflareaccess.com',
      'cloudflareresearch.com', 'acme-v02.api.letsencrypt.org', 'engage.cloudflareclient.com',
      'time.cloudflare.com', 'imap.hostinger.com', 'smtp.hostinger.com', 'help.stockbit.com',
      'chat.riotgames.com', 'gitlab.com',
    ],
    aliases_wanted: 8,
    min_ok: 3,
    refresh_interval_h: 6,
  },
  tuning: { udp_buffer_bytes: 16777216, tcp_workers: 0, extra_lua: '' },
  webserver: { listen: '127.0.0.1:8083', prometheus_acl: ['127.0.0.1/32'] },
  analytics: { enabled: true, sample_rate: 1, top_k: 5000, stream_addr: '127.0.0.1:6001' },
})

type Obj = Record<string, unknown>
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v)

/** Go marshals nil slices as null and older specs may miss keys: fill both from the defaults. */
export function normalizeSpec(spec: ConfigSpec): ConfigSpec {
  const fill = (def: unknown, v: unknown): unknown => {
    if (v === undefined || v === null) return Array.isArray(def) ? [] : def
    if (!isObj(def) || !isObj(v)) return v
    const out: Obj = { ...v }
    for (const k of Object.keys(def)) out[k] = fill(def[k], v[k])
    return out
  }
  return fill(defaultSpec(), spec) as ConfigSpec
}

/** Field path → messages. Key '' holds lines that name no field. */
export type SpecErrors = Record<string, string[]>

const FIELD_RE =
  /\b((?:listen|acl|upstreams|cache|blocking|abuse|cgk|tuning|webserver|analytics)(?:\[\d+\])?(?:\.[a-z0-9_]+(?:\[\d+\])?)*): (.+)$/

/** Parses spec.Validate() output ("field: message" lines joined by "\n", maybe prefixed) into per-field errors. */
export function parseSpecErrors(message: string): SpecErrors {
  const out: SpecErrors = {}
  for (const line of message.split('\n').map((l) => l.trim()).filter(Boolean)) {
    const m = line.match(FIELD_RE)
    const [key, msg] = m ? [m[1], m[2]] : ['', line]
    ;(out[key] ??= []).push(msg)
  }
  return out
}

export const POLICY_INFO: Record<ServerPolicy, { label: string; help: string; weighted: boolean }> = {
  whashed: {
    label: 'Weighted hash',
    help: 'Hashes the query name so a given name always goes to the same upstream (better upstream cache reuse), spread by weight.',
    weighted: true,
  },
  wrandom: { label: 'Weighted random', help: 'Picks a random healthy upstream for every query, in proportion to its weight.', weighted: true },
  leastOutstanding: {
    label: 'Least outstanding',
    help: 'Sends to the upstream with the fewest in-flight queries, then lowest order, then lowest latency. Weights are ignored.',
    weighted: false,
  },
  roundrobin: { label: 'Round robin', help: 'Rotates through all healthy upstreams in turn. Weights are ignored.', weighted: false },
  firstAvailable: {
    label: 'First available',
    help: 'Uses the healthy upstream with the lowest order; higher orders only take over on failure. Weights are ignored.',
    weighted: false,
  },
}
