// Exact mirror of internal/shared/api (docs/SPEC.md §6, §8, §10). Field names match the wire format.
// Go → TS: time.Time → RFC 3339 string; *T → T | null; `omitempty` → optional; json.RawMessage → unknown JSON.
// Agent-only DTOs (EnrollRequest, AgentConfig, BlockedBatch, NodeRuntime) are not mirrored; EnrollResponse is.

// ─── §6 ConfigSpec (config.go) ─────────────────────────────────────────────
export interface Do53 {
  enabled: boolean
  addresses: string[]
  reuse_port_listeners: number
}
export interface DoH {
  enabled: boolean
  addresses: string[]
  path: string
}
export interface DoT {
  enabled: boolean
  addresses: string[]
}
export interface TLS {
  cert_file: string
  key_file: string
}
export interface Listen {
  do53: Do53
  doh: DoH
  dot: DoT
  tls: TLS
}

export type ServerPolicy = 'whashed' | 'wrandom' | 'leastOutstanding' | 'roundrobin' | 'firstAvailable'
export const POLICIES: ServerPolicy[] = ['whashed', 'wrandom', 'leastOutstanding', 'roundrobin', 'firstAvailable']
export interface Upstream {
  address: string
  weight: number
  order: number
  sockets: number
  name: string
}
export interface Upstreams {
  policy: ServerPolicy
  servers: Upstream[]
  health_check_interval_s: number
}

export interface Cache {
  enabled: boolean
  max_entries: number
  min_ttl: number
  max_ttl: number
  stale_ttl: number
}

export interface Blocking {
  enabled: boolean
  blockpage_ipv4: string
  blockpage_ipv6: string
  txt: string
  soa: string
  ns: string
  block_response_ips: boolean
  log_blocked: boolean
}

export type DynAction = 'truncate' | 'drop' | 'refused'
export const DYN_ACTIONS: DynAction[] = ['truncate', 'drop', 'refused']
export interface Abuse {
  enabled: boolean
  per_client_qps: number
  per_client_burst: number
  dyn_query_rate: number
  dyn_nxdomain_rate: number
  dyn_servfail_rate: number
  dyn_window_s: number
  dyn_block_s: number
  dyn_action: DynAction
  trusted: string[]
}

export interface CGK {
  enabled: boolean
  rewrite_pools: string[]
  alias_pools: string[]
  test_sites: string[]
  exclude: string[]
  aliases_wanted: number
  min_ok: number
  refresh_interval_h: number
}

export interface Tuning {
  udp_buffer_bytes: number
  tcp_workers: number
  extra_lua: string
}

export interface Webserver {
  listen: string
  prometheus_acl: string[]
}

export interface ConfigSpec {
  listen: Listen
  acl: string[]
  upstreams: Upstreams
  cache: Cache
  blocking: Blocking
  abuse: Abuse
  cgk: CGK
  tuning: Tuning
  webserver: Webserver
}

// ─── §8 Heartbeat & CGK (agent.go) ─────────────────────────────────────────
export interface SystemStats {
  load1: number
  mem_total_mb: number
  mem_avail_mb: number
  disk_free_mb: number
}

export interface Counters {
  queries: number
  responses: number
  cache_hits: number
  cache_misses: number
  blocked: number
  dyn_blocked: number
  rule_drops: number
  servfail: number
  nxdomain: number
  noerror: number
  cgk_rewrites: number
}

export interface BackendStat {
  address: string
  name: string
  pool: string
  state: string // raw dnsdist state: "up" | "down" | …
  weight: number
  order: number
  qps: number
  latency_ms: number
  queries: number
  drops: number
}

export type OffenderStage = 'warning' | 'blocked'
export interface DynBlock {
  client: string
  reason: string
  stage: OffenderStage
  seconds_left: number
  blocks: number
}

export interface CGKStatus {
  aliases: number
  rewrite_ranges: number
  last_refresh?: string
  last_error: string
}

export interface Heartbeat {
  time: string
  agent_version: string
  dnsdist_version: string
  os: string
  uptime_s: number
  dnsdist_running: boolean
  applied_config_version: number
  apply_error: string
  blocklist_sha256: string
  blocklist_error: string
  system: SystemStats
  counters: Counters
  latency_avg_ms: number
  backends: BackendStat[]
  dynblocks: DynBlock[]
  cgk: CGKStatus
  acked_commands?: number[]
  dnsdist_candidate: string
  dnsdist_available: string[] | null
  dnsdist_repo_series: string
  inventory_at: string | null
  last_upgrade: UpgradeResult | null
  upgrade_in_progress: boolean
}

export type UpgradeKind = 'dnsdist' | 'agent'
export interface UpgradeResult {
  kind: UpgradeKind
  from: string
  to: string
  ok: boolean
  error: string
  at: string
}

export type CommandType =
  | 'cgk_refresh'
  | 'restart_dnsdist'
  | 'reapply'
  | 'check_updates'
  | 'upgrade_dnsdist'
  | 'set_dnsdist_series'
  | 'upgrade_agent'
/** version: upgrade_dnsdist only (one of the node's dnsdist_available); series: set_dnsdist_series only (Meta.supported_series). */
export interface CommandRequest {
  type: CommandType
  version?: string
  series?: string
}
export interface Command {
  id: number
  type: CommandType
  version?: string
  series?: string
}

export interface EnrollResponse {
  node_id: string
  name: string
  node_token: string
  poll_interval_s: number
}

export interface CGKPool {
  net: string
  colos: string[]
}
export interface CGKReport {
  measured_at: string
  aliases: string[]
  rewrite_ranges: string[]
  pools: CGKPool[]
  ok: boolean
  message: string
}

// ─── §10 panel DTOs (panel.go, contract_extra.go) ──────────────────────────
export interface List<T> {
  items: T[]
  total: number
}

export interface ErrorBody {
  error: { code: string; message: string }
}

export type Role = 'admin' | 'viewer'
export interface User {
  id: string
  email: string
  name: string
  role: Role
  disabled: boolean
  created_at: string
  last_login_at: string | null
}

export interface LoginRequest {
  email: string
  password: string
}
/** Returned by POST /auth/login and GET /auth/me. */
export interface Session {
  user: User
  expires_at: string
}
export interface PasswordChange {
  current: string
  new: string
}
export interface UserCreate {
  email: string
  name: string
  password: string
  role: Role
}
export interface UserPatch {
  name?: string
  role?: Role
  disabled?: boolean
  password?: string
}

export type NodeStatus = 'pending' | 'online' | 'degraded' | 'offline'
export type Labels = Record<string, string>

export interface Node {
  id: string
  name: string
  hostname: string
  public_ip: string
  labels: Labels
  status: NodeStatus
  profile_id: string | null
  profile_name: string
  overrides: unknown // RFC 7396 merge patch over the profile spec (null when none)
  enrolled_at: string | null
  last_seen_at: string | null
  agent_version: string
  dnsdist_version: string
  os: string
  arch: string
  applied_config_version: number | null
  applied_blocklist_sha256: string
  last_error: string
  created_at: string
  desired_config_version: number | null
  desired_blocklist_sha256: string
  config_in_sync: boolean
  blocklist_in_sync: boolean
  qps: number
  cache_hit_ratio: number
  latency_avg_ms: number
  dnsdist_candidate: string
  dnsdist_available: string[]
  dnsdist_repo_series: string
  inventory_at: string | null
  last_upgrade: UpgradeResult | null
  agent_outdated: boolean
}

export interface NodePatch {
  name?: string
  labels?: Labels
  profile_id?: string
  overrides?: unknown
}

/** GET /nodes/{id}/live — heartbeat is null until the first one arrives. */
export interface NodeLive {
  node_id: string
  received_at: string | null
  heartbeat: Heartbeat | null
}

export interface MetricPoint {
  ts: string
  queries: number
  responses: number
  cache_hits: number
  cache_misses: number
  blocked: number
  dyn_blocked: number
  rule_drops: number
  servfail: number
  nxdomain: number
  noerror: number
  cgk_rewrites: number
  latency_avg_ms: number
}

export interface Metrics {
  from: string
  to: string
  step_s: number
  points: MetricPoint[]
}

/** A MetricPoint plus values derived for its step. */
export interface MetricSample extends MetricPoint {
  qps: number // queries / step seconds
  cache_hit_ratio: number // 0..1
}

/** GET /nodes/{id}/metrics and GET /overview/metrics (fleet sum). Empty buckets are present with zeros. */
export interface MetricSeries {
  from: string
  to: string
  step_s: number
  points: MetricSample[]
}

/** Query string of the metrics routes: from/to RFC 3339, step a Go duration (≥ 1m, e.g. "5m"). */
export interface MetricsQuery {
  from?: string
  to?: string
  step?: string
}

/** GET /nodes/{id}/config/rendered and POST /profiles/{id}/preview. Secrets are masked. */
export interface RenderedConfig {
  spec: ConfigSpec
  files: Record<string, string>
}

export interface Profile {
  id: string
  name: string
  description: string
  created_at: string
  latest_version: number
  published_version: number | null
  nodes: number
}

export interface ProfileRequest {
  name?: string
  description?: string
  /** Create only: profile id whose newest published spec becomes version 1 (default: built-in defaults). */
  copy_from?: string
}

export interface ConfigVersion {
  id: number
  profile_id: string
  version: number
  spec: ConfigSpec
  comment: string
  created_by: string | null
  created_at: string
  published: boolean
  published_at: string | null
}

export interface VersionCreate {
  spec: ConfigSpec
  comment: string
}

export interface PreviewRequest {
  spec: ConfigSpec
}

export interface VersionDiff {
  a: ConfigVersion
  b: ConfigVersion
}

export interface SpecChange {
  path: string // e.g. "upstreams.servers[0].weight"; "" = whole spec
  op: 'add' | 'remove' | 'replace'
  old: unknown // null for add
  new: unknown // null for remove
}

/** GET /profiles/{id}/versions/{a}/diff/{b}: both versions plus the changes that turn a into b. */
export interface ConfigVersionDiff extends VersionDiff {
  changes: SpecChange[]
}

export interface EnrollmentToken {
  id: string
  node_name: string
  labels: Labels
  profile_id: string | null
  created_by: string | null
  created_at: string
  expires_at: string
  used_at: string | null
  used_by_node: string | null
}

export interface EnrollmentTokenCreate {
  node_name: string
  labels: Labels
  profile_id: string | null
  ttl_hours: number
}

/** The only time the plaintext token is shown. */
export interface EnrollmentTokenCreated {
  id: string
  token: string
  install_command: string
  expires_at: string
}

export type BlocklistSourceKind =
  | 'trustpositif_domains'
  | 'trustpositif_ips'
  | 'url_domains'
  | 'url_ips'
  | 'manual_domains'
  | 'manual_ips'
  | 'whitelist'

export interface BlocklistSource {
  id: string
  name: string
  kind: BlocklistSourceKind
  url: string
  content: string
  enabled: boolean
  etag: string
  last_modified: string
  last_fetch_at: string | null
  last_status: string
  entries: number
  created_at: string
  updated_at: string
}

export interface BlocklistSourceCreate {
  name: string
  kind: BlocklistSourceKind
  url: string
  content: string
  enabled?: boolean
}

export interface BlocklistSourcePatch {
  name?: string
  url?: string
  content?: string
  enabled?: boolean
}

export type BuildStatus = 'running' | 'ok' | 'failed' | 'skipped'
export interface BlocklistBuild {
  id: number
  started_at: string
  finished_at: string | null
  status: BuildStatus
  trigger: 'schedule' | 'manual'
  domains: number
  ips: number
  whitelisted: number
  skipped: number
  size_bytes: number
  sha256: string
  error: string
}

export interface BlocklistLookup {
  name: string
  blocked: boolean
  match: string // the entry that matched (the name itself or a parent)
}

export interface BlockedReportQuery {
  from?: string
  to?: string
  node_id?: string
  limit?: number
}

export type CSVKind = 'summary' | 'monthly' | 'top'

export interface BlockedByNode {
  node_id: string
  node_name: string
  count: number
}
export interface BlockedByMonth {
  month: string // YYYY-MM
  count: number
}
export interface TopDomain {
  qname: string
  count: number
}
export interface BlockedReport {
  total: number
  by_node: BlockedByNode[]
  by_month: BlockedByMonth[]
  top_domains: TopDomain[]
}

export interface Offender {
  id: number
  node_id: string
  node_name: string
  client: string
  stage: OffenderStage
  reason: string
  first_seen: string
  last_seen: string
  blocks: number
  closed: boolean
}

export interface OffendersQuery {
  active?: boolean
  node_id?: string
}

export interface AuditEntry {
  id: number
  at: string
  user_id: string | null
  user_email: string
  action: string
  target_type: string
  target_id: string
  details: unknown
  ip: string
}

export interface AuditQuery {
  limit?: number
  before?: number // audit id; returns older entries
}

/** PUT decodes over the current values, so a partial body is fine. public_url "" = DNSJOS_PUBLIC_URL. */
export interface Settings {
  blocklist_build_interval_minutes: number
  metrics_retention_days: number
  blocked_retention_days: number
  agent_poll_interval_s: number
  agent_heartbeat_interval_s: number
  public_url: string
}

export interface Overview {
  nodes: Partial<Record<NodeStatus, number>> // by status; missing = 0
  nodes_total: number
  qps: number
  cache_hit_ratio: number
  blocked_24h: number
  current_build: BlocklistBuild | null
  active_offenders: number
}

// ─── §18 upgrades (upgrades.go) ────────────────────────────────────────────
/** GET /nodes/{id}/versions */
export interface NodeVersions {
  installed: string
  candidate: string
  available: string[]
  series: string
  inventory_at: string | null
  last_upgrade: UpgradeResult | null
  upgrade_in_progress: boolean
  agent_version: string
  panel_agent_version: string
  agent_outdated: boolean
}

export type UpgradeRunStatus = 'running' | 'paused' | 'done' | 'failed' | 'aborted'
export type UpgradeStepStatus = 'pending' | 'running' | 'ok' | 'failed' | 'skipped'

export interface UpgradeRunStep {
  position: number
  node_id: string
  node_name: string
  status: UpgradeStepStatus
  started_at: string | null
  finished_at: string | null
  message: string
  from_version: string
  to_version: string
}

export interface UpgradeRun {
  id: number
  kind: UpgradeKind
  target_version: string
  status: UpgradeRunStatus
  created_by: string | null
  created_at: string
  finished_at: string | null
  message: string
  steps: UpgradeRunStep[]
}

/** node_ids omitted = every live node, least busy first. target_version: required for dnsdist, "" for agent = embedded version. */
export interface UpgradeRunCreate {
  kind: UpgradeKind
  target_version: string
  node_ids?: string[]
}

export type UpgradeAction = 'pause' | 'resume' | 'abort'

/** GET /meta */
export interface Meta {
  panel_version: string
  agent_version: string
  supported_series: string[]
}
