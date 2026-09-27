import { QueryClient, useMutation, useQuery, useQueryClient, type QueryKey } from '@tanstack/react-query'
import type {
  AnalyticsKind,
  AnalyticsQuery,
  AnalyticsReport,
  AllowEntry,
  AllowEntryCreate,
  APIToken,
  APITokenCreate,
  APITokenCreated,
  AuditEntry,
  AuditQuery,
  BlockedReport,
  Branding,
  BlockedReportQuery,
  BlocklistBuild,
  BlocklistLookup,
  BlocklistSource,
  BlocklistSourceCreate,
  BlocklistSourcePatch,
  CGKReport,
  Command,
  CommandRequest,
  ConfigSpec,
  ConfigVersion,
  ConfigVersionDiff,
  CSVKind,
  EnrollmentToken,
  EnrollmentTokenCreate,
  EnrollmentTokenCreated,
  List,
  Meta,
  MetricSeries,
  MetricsQuery,
  Node,
  NodeLive,
  NodePatch,
  NodeVersions,
  Offender,
  OffendersQuery,
  Overview,
  PasswordChange,
  Profile,
  ProfileRequest,
  RenderedConfig,
  Session,
  Settings,
  UpgradeAction,
  UpgradeRun,
  UpgradeRunCreate,
  User,
  UserCreate,
  UserPatch,
} from './types'

// ─── fetch wrapper ─────────────────────────────────────────────────────────

export class ApiError extends Error {
  code: string
  status: number
  constructor(code: string, message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.code = code
    this.status = status
  }
}

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5_000,
      refetchOnWindowFocus: false,
      retry: (n, err) => !(err instanceof ApiError && err.status < 500) && n < 2,
    },
  },
})

type Params = Record<string, string | number | boolean | undefined | null>

export function qs(params?: Params): string {
  if (!params) return ''
  const sp = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') sp.set(k, String(v))
  const s = sp.toString()
  return s ? `?${s}` : ''
}

export async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { 'X-Requested-With': 'dnsjos', Accept: 'application/json' }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  const res = await fetch(path, {
    method,
    headers,
    credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (res.status === 204) return undefined as T
  const data: unknown = res.headers.get('content-type')?.includes('json') ? await res.json().catch(() => null) : null
  if (!res.ok) {
    const e = (data as { error?: { code?: string; message?: string } } | null)?.error
    const err = new ApiError(e?.code ?? 'http_' + res.status, e?.message ?? res.statusText, res.status)
    // Session expired: drop the cached user so RequireAuth redirects to /login.
    if (res.status === 401 && !path.startsWith('/api/v1/auth/')) queryClient.setQueryData(qk.me, null)
    throw err
  }
  return data as T
}

const get = <T>(p: string) => request<T>('GET', p)
const post = <T>(p: string, b?: unknown) => request<T>('POST', p, b ?? {})
const patch = <T>(p: string, b: unknown) => request<T>('PATCH', p, b)
const put = <T>(p: string, b: unknown) => request<T>('PUT', p, b)
const del = (p: string) => request<void>('DELETE', p)

const V1 = '/api/v1'
const enc = encodeURIComponent

// ─── endpoints (SPEC §10) ──────────────────────────────────────────────────

export const api = {
  auth: {
    login: (email: string, password: string) => post<Session>(`${V1}/auth/login`, { email, password }),
    logout: () => post<void>(`${V1}/auth/logout`),
    me: () => get<Session>(`${V1}/auth/me`),
    changePassword: (p: PasswordChange) => patch<void>(`${V1}/auth/password`, p),
  },
  users: {
    list: () => get<List<User>>(`${V1}/users`),
    create: (u: UserCreate) => post<User>(`${V1}/users`, u),
    update: (id: string, u: UserPatch) => patch<User>(`${V1}/users/${id}`, u),
    remove: (id: string) => del(`${V1}/users/${id}`),
  },
  apiTokens: {
    list: () => get<List<APIToken>>(`${V1}/api-tokens`),
    create: (t: APITokenCreate) => post<APITokenCreated>(`${V1}/api-tokens`, t),
    revoke: (id: string) => del(`${V1}/api-tokens/${id}`),
  },
  nodes: {
    list: () => get<List<Node>>(`${V1}/nodes`),
    get: (id: string) => get<Node>(`${V1}/nodes/${id}`),
    update: (id: string, p: NodePatch) => patch<Node>(`${V1}/nodes/${id}`, p),
    remove: (id: string) => del(`${V1}/nodes/${id}`),
    live: (id: string) => get<NodeLive>(`${V1}/nodes/${id}/live`),
    metrics: (id: string, q: MetricsQuery = {}) => get<MetricSeries>(`${V1}/nodes/${id}/metrics${qs({ ...q })}`),
    command: (id: string, c: CommandRequest) => post<Command>(`${V1}/nodes/${id}/commands`, c),
    versions: (id: string) => get<NodeVersions>(`${V1}/nodes/${id}/versions`),
    rendered: (id: string) => get<RenderedConfig>(`${V1}/nodes/${id}/config/rendered`),
    cgk: (id: string) => get<CGKReport | null>(`${V1}/nodes/${id}/cgk`),
  },
  enrollment: {
    list: () => get<List<EnrollmentToken>>(`${V1}/enrollment-tokens`),
    create: (t: EnrollmentTokenCreate) => post<EnrollmentTokenCreated>(`${V1}/enrollment-tokens`, t),
    remove: (id: string) => del(`${V1}/enrollment-tokens/${id}`),
  },
  profiles: {
    list: () => get<List<Profile>>(`${V1}/profiles`),
    get: (id: string) => get<Profile>(`${V1}/profiles/${id}`),
    create: (p: ProfileRequest) => post<Profile>(`${V1}/profiles`, p),
    update: (id: string, p: ProfileRequest) => patch<Profile>(`${V1}/profiles/${id}`, p),
    remove: (id: string) => del(`${V1}/profiles/${id}`),
    versions: (id: string) => get<List<ConfigVersion>>(`${V1}/profiles/${id}/versions`),
    version: (id: string, v: number) => get<ConfigVersion>(`${V1}/profiles/${id}/versions/${v}`),
    createVersion: (id: string, spec: ConfigSpec, comment: string) =>
      post<ConfigVersion>(`${V1}/profiles/${id}/versions`, { spec, comment }),
    publish: (id: string, v: number) => post<ConfigVersion>(`${V1}/profiles/${id}/versions/${v}/publish`),
    diff: (id: string, a: number, b: number) => get<ConfigVersionDiff>(`${V1}/profiles/${id}/versions/${a}/diff/${b}`),
    preview: (id: string, spec: ConfigSpec) => post<RenderedConfig>(`${V1}/profiles/${id}/preview`, { spec }),
  },
  blocklist: {
    sources: () => get<List<BlocklistSource>>(`${V1}/blocklist/sources`),
    createSource: (s: BlocklistSourceCreate) => post<BlocklistSource>(`${V1}/blocklist/sources`, s),
    updateSource: (id: string, s: BlocklistSourcePatch) => patch<BlocklistSource>(`${V1}/blocklist/sources/${id}`, s),
    removeSource: (id: string) => del(`${V1}/blocklist/sources/${id}`),
    builds: () => get<List<BlocklistBuild>>(`${V1}/blocklist/builds`),
    build: (force = false) => post<BlocklistBuild>(`${V1}/blocklist/builds${force ? '?force=true' : ''}`),
    current: () => get<BlocklistBuild | null>(`${V1}/blocklist/current`),
    lookup: (name: string) => get<BlocklistLookup>(`${V1}/blocklist/lookup?name=${enc(name)}`),
  },
  allowlist: {
    list: () => get<List<AllowEntry>>(`${V1}/allowlist`),
    create: (e: AllowEntryCreate) => post<AllowEntry>(`${V1}/allowlist`, e),
    remove: (id: string) => del(`${V1}/allowlist/${id}`),
  },
  reports: {
    blocked: (q: BlockedReportQuery = {}) => get<BlockedReport>(`${V1}/reports/blocked${qs({ ...q })}`),
    /** URL for an <a href download> — the browser sends the session cookie. */
    blockedCsvUrl: (q: BlockedReportQuery & { kind: CSVKind }) => `${V1}/reports/blocked.csv${qs({ ...q })}`,
  },
  analytics: {
    report: (q: AnalyticsQuery = {}) => get<AnalyticsReport>(`${V1}/analytics${qs({ ...q })}`),
    /** URL for an <a href download>; the filename carries kind and range. */
    csvUrl: (q: AnalyticsQuery & { kind: AnalyticsKind }) => `${V1}/analytics.csv${qs({ ...q })}`,
  },
  offenders: {
    list: (q: OffendersQuery = {}) => get<List<Offender>>(`${V1}/offenders${qs({ ...q })}`),
  },
  audit: {
    list: (q: AuditQuery = {}) => get<List<AuditEntry>>(`${V1}/audit${qs({ ...q })}`),
  },
  settings: {
    get: () => get<Settings>(`${V1}/settings`),
    update: (s: Partial<Settings>) => put<Settings>(`${V1}/settings`, s),
  },
  upgrades: {
    list: () => get<List<UpgradeRun>>(`${V1}/upgrades`),
    get: (id: number) => get<UpgradeRun>(`${V1}/upgrades/${id}`),
    create: (c: UpgradeRunCreate) => post<UpgradeRun>(`${V1}/upgrades`, c),
    action: (id: number, action: UpgradeAction) => post<UpgradeRun>(`${V1}/upgrades/${id}/${action}`),
  },
  meta: () => get<Meta>(`${V1}/meta`),
  branding: () => get<Branding>(`${V1}/branding`),
  overview: {
    get: () => get<Overview>(`${V1}/overview`),
    metrics: (q: MetricsQuery = {}) => get<MetricSeries>(`${V1}/overview/metrics${qs({ ...q })}`),
  },
}

// ─── query keys & hooks ────────────────────────────────────────────────────

export const qk = {
  me: ['me'] as const,
  overview: ['overview'] as const,
  fleetMetrics: (q: MetricsQuery) => ['overview', 'metrics', q] as const,
  nodes: ['nodes'] as const,
  node: (id: string) => ['nodes', id] as const,
  nodeLive: (id: string) => ['nodes', id, 'live'] as const,
  nodeMetrics: (id: string, q: MetricsQuery) => ['nodes', id, 'metrics', q] as const,
  nodeRendered: (id: string) => ['nodes', id, 'rendered'] as const,
  nodeCGK: (id: string) => ['nodes', id, 'cgk'] as const,
  nodeVersions: (id: string) => ['nodes', id, 'versions'] as const,
  upgrades: ['upgrades'] as const,
  upgrade: (id: number) => ['upgrades', id] as const,
  meta: ['meta'] as const,
  branding: ['branding'] as const,
  enrollment: ['enrollment-tokens'] as const,
  profiles: ['profiles'] as const,
  profile: (id: string) => ['profiles', id] as const,
  profileVersions: (id: string) => ['profiles', id, 'versions'] as const,
  profileVersion: (id: string, v: number) => ['profiles', id, 'versions', v] as const,
  versionDiff: (id: string, a: number, b: number) => ['profiles', id, 'diff', a, b] as const,
  blocklistSources: ['blocklist', 'sources'] as const,
  blocklistBuilds: ['blocklist', 'builds'] as const,
  blocklistCurrent: ['blocklist', 'current'] as const,
  blocklistLookup: (name: string) => ['blocklist', 'lookup', name] as const,
  allowlist: ['allowlist'] as const,
  blocked: (q: BlockedReportQuery) => ['reports', 'blocked', q] as const,
  analytics: (q: AnalyticsQuery) => ['analytics', q] as const,
  offenders: (q: OffendersQuery) => ['offenders', q] as const,
  users: ['users'] as const,
  apiTokens: ['api-tokens'] as const,
  audit: (q: AuditQuery) => ['audit', q] as const,
  settings: ['settings'] as const,
}

const LIVE = 10_000

/** Current user, or null when not signed in. */
export const useMe = () =>
  useQuery({
    queryKey: qk.me,
    queryFn: () =>
      api.auth.me().then(
        (s) => s.user,
        (e: unknown) => {
          if (e instanceof ApiError && e.status === 401) return null
          throw e
        },
      ),
    staleTime: Infinity,
  })

export const useOverview = () => useQuery({ queryKey: qk.overview, queryFn: api.overview.get, refetchInterval: LIVE })
export const useFleetMetrics = (q: MetricsQuery = {}, refetchInterval: number | false = 60_000) =>
  useQuery({ queryKey: qk.fleetMetrics(q), queryFn: () => api.overview.metrics(q), refetchInterval })
export const useNodes = () => useQuery({ queryKey: qk.nodes, queryFn: api.nodes.list, refetchInterval: LIVE })
export const useNode = (id: string) => useQuery({ queryKey: qk.node(id), queryFn: () => api.nodes.get(id) })
export const useNodeLive = (id: string) =>
  useQuery({ queryKey: qk.nodeLive(id), queryFn: () => api.nodes.live(id), refetchInterval: LIVE })
export const useNodeMetrics = (id: string, q: MetricsQuery = {}, refetchInterval: number | false = 60_000) =>
  useQuery({ queryKey: qk.nodeMetrics(id, q), queryFn: () => api.nodes.metrics(id, q), refetchInterval })
export const useNodeRendered = (id: string) =>
  useQuery({ queryKey: qk.nodeRendered(id), queryFn: () => api.nodes.rendered(id) })
export const useNodeCGK = (id: string) =>
  useQuery({ queryKey: qk.nodeCGK(id), queryFn: () => api.nodes.cgk(id), refetchInterval: 60_000 })
export const useNodeVersions = (id: string) =>
  useQuery({ queryKey: qk.nodeVersions(id), queryFn: () => api.nodes.versions(id), refetchInterval: LIVE })
export const useUpgrades = () => useQuery({ queryKey: qk.upgrades, queryFn: api.upgrades.list, refetchInterval: LIVE })
/** Polls every 3 s while the run is running. */
export const useUpgrade = (id: number) =>
  useQuery({
    queryKey: qk.upgrade(id),
    queryFn: () => api.upgrades.get(id),
    refetchInterval: (q) => (q.state.data?.status === 'running' ? 3_000 : false),
  })
export const useMeta = () => useQuery({ queryKey: qk.meta, queryFn: api.meta, staleTime: Infinity })
/** Public runtime branding (works signed out); fixed for the page's lifetime. */
export const useBranding = () => useQuery({ queryKey: qk.branding, queryFn: api.branding, staleTime: Infinity })
export const useEnrollmentTokens = () => useQuery({ queryKey: qk.enrollment, queryFn: api.enrollment.list })
export const useProfiles = () => useQuery({ queryKey: qk.profiles, queryFn: api.profiles.list })
export const useProfile = (id: string) => useQuery({ queryKey: qk.profile(id), queryFn: () => api.profiles.get(id) })
export const useProfileVersions = (id: string) =>
  useQuery({ queryKey: qk.profileVersions(id), queryFn: () => api.profiles.versions(id) })
export const useProfileVersion = (id: string, v: number | undefined) =>
  useQuery({
    queryKey: qk.profileVersion(id, v ?? 0),
    queryFn: () => api.profiles.version(id, v ?? 0),
    enabled: v !== undefined,
  })
export const useVersionDiff = (id: string, a: number | undefined, b: number | undefined) =>
  useQuery({
    queryKey: qk.versionDiff(id, a ?? 0, b ?? 0),
    queryFn: () => api.profiles.diff(id, a ?? 0, b ?? 0),
    enabled: a !== undefined && b !== undefined,
  })
export const useBlocklistSources = () => useQuery({ queryKey: qk.blocklistSources, queryFn: api.blocklist.sources })
export const useBlocklistBuilds = () =>
  useQuery({ queryKey: qk.blocklistBuilds, queryFn: api.blocklist.builds, refetchInterval: LIVE })
export const useBlocklistCurrent = () =>
  useQuery({ queryKey: qk.blocklistCurrent, queryFn: api.blocklist.current, refetchInterval: LIVE })
/** Disabled while name is empty. */
export const useBlocklistLookup = (name: string) =>
  useQuery({ queryKey: qk.blocklistLookup(name), queryFn: () => api.blocklist.lookup(name), enabled: name !== '' })
export const useAllowlist = () => useQuery({ queryKey: qk.allowlist, queryFn: api.allowlist.list })
export const useBlockedReport = (q: BlockedReportQuery) =>
  useQuery({ queryKey: qk.blocked(q), queryFn: () => api.reports.blocked(q) })
export const useAnalytics = (q: AnalyticsQuery) =>
  useQuery({ queryKey: qk.analytics(q), queryFn: () => api.analytics.report(q) })
export const useOffenders = (q: OffendersQuery = {}) =>
  useQuery({ queryKey: qk.offenders(q), queryFn: () => api.offenders.list(q), refetchInterval: LIVE })
export const useAPITokens = () => useQuery({ queryKey: qk.apiTokens, queryFn: api.apiTokens.list })
export const useUsers = (enabled = true) => useQuery({ queryKey: qk.users, queryFn: api.users.list, enabled })
export const useAudit = (q: AuditQuery = {}) => useQuery({ queryKey: qk.audit(q), queryFn: () => api.audit.list(q) })
export const useSettings = () => useQuery({ queryKey: qk.settings, queryFn: api.settings.get })

/** useMutation that invalidates the given query-key prefixes on success. */
function useMut<A, R>(fn: (a: A) => Promise<R>, invalidate: (a: A) => QueryKey[]) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: fn,
    onSuccess: (_r, a) => Promise.all(invalidate(a).map((queryKey) => qc.invalidateQueries({ queryKey }))),
  })
}

export const useLogin = () => {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ email, password }: { email: string; password: string }) => api.auth.login(email, password),
    onSuccess: ({ user }) => qc.setQueryData(qk.me, user),
  })
}
export const useLogout = () => {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: api.auth.logout,
    onSettled: () => {
      qc.clear()
      qc.setQueryData(qk.me, null)
    },
  })
}
export const useChangePassword = () => useMutation({ mutationFn: api.auth.changePassword })

export const useUpdateNode = () =>
  useMut(
    (a: { id: string; patch: NodePatch }) => api.nodes.update(a.id, a.patch),
    (a) => [qk.nodes, qk.overview, qk.nodeRendered(a.id)],
  )
export const useDeleteNode = () => useMut(api.nodes.remove, () => [qk.nodes, qk.overview])
export const useNodeCommand = () =>
  useMut(
    ({ id, ...c }: { id: string } & CommandRequest) => api.nodes.command(id, c),
    (a) => [qk.node(a.id)],
  )
/** Renders a spec without saving it (profile editor "Preview Lua"). */
export const usePreview = () =>
  useMutation({ mutationFn: (a: { id: string; spec: ConfigSpec }) => api.profiles.preview(a.id, a.spec) })

export const useCreateEnrollmentToken = () => useMut(api.enrollment.create, () => [qk.enrollment])
export const useDeleteEnrollmentToken = () => useMut(api.enrollment.remove, () => [qk.enrollment])

export const useCreateProfile = () => useMut(api.profiles.create, () => [qk.profiles])
export const useUpdateProfile = () =>
  useMut((a: { id: string } & ProfileRequest) => api.profiles.update(a.id, a), () => [qk.profiles])
export const useDeleteProfile = () => useMut(api.profiles.remove, () => [qk.profiles])
export const useCreateVersion = () =>
  useMut(
    (a: { id: string; spec: ConfigSpec; comment: string }) => api.profiles.createVersion(a.id, a.spec, a.comment),
    () => [qk.profiles],
  )
export const usePublishVersion = () =>
  useMut((a: { id: string; version: number }) => api.profiles.publish(a.id, a.version), () => [qk.profiles, qk.nodes])

export const useCreateSource = () => useMut(api.blocklist.createSource, () => [qk.blocklistSources])
export const useUpdateSource = () =>
  useMut(
    (a: { id: string; patch: BlocklistSourcePatch }) => api.blocklist.updateSource(a.id, a.patch),
    () => [qk.blocklistSources],
  )
export const useDeleteSource = () => useMut(api.blocklist.removeSource, () => [qk.blocklistSources])
export const useBuildNow = () =>
  useMut((force: boolean = false) => api.blocklist.build(force), () => [
    qk.blocklistBuilds,
    qk.blocklistCurrent,
    qk.blocklistSources,
    qk.overview,
  ])

export const useAddAllow = () => useMut(api.allowlist.create, () => [qk.allowlist, ['blocklist', 'lookup']])
export const useDeleteAllow = () => useMut(api.allowlist.remove, () => [qk.allowlist, ['blocklist', 'lookup']])

export const useCreateUser = () => useMut(api.users.create, () => [qk.users])
export const useUpdateUser = () =>
  useMut((a: { id: string; patch: UserPatch }) => api.users.update(a.id, a.patch), () => [qk.users, qk.me])
export const useDeleteUser = () => useMut(api.users.remove, () => [qk.users])

export const useCreateAPIToken = () => useMut(api.apiTokens.create, () => [qk.apiTokens])
export const useRevokeAPIToken = () => useMut(api.apiTokens.revoke, () => [qk.apiTokens])

export const useCreateUpgrade = () => useMut(api.upgrades.create, () => [qk.upgrades, qk.nodes])
export const useUpgradeAction = () =>
  useMut(
    (a: { id: number; action: UpgradeAction }) => api.upgrades.action(a.id, a.action),
    () => [qk.upgrades, qk.nodes],
  )

export const useUpdateSettings = () => useMut(api.settings.update, () => [qk.settings])
