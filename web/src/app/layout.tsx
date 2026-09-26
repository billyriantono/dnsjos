import type { IconType } from 'react-icons'
import {
  LuChartNoAxesColumn,
  LuFileChartColumn,
  LuLayoutDashboard,
  LuPackageCheck,
  LuScrollText,
  LuServer,
  LuSettings,
  LuShieldBan,
  LuSiren,
  LuSlidersHorizontal,
  LuUsers,
} from 'react-icons/lu'
import { Link, Outlet, useMatch, useMatches } from 'react-router'

import { Separator } from '@/components/ui/separator'
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarRail,
  SidebarTrigger,
  useSidebar,
} from '@/components/ui/sidebar'
import { useOverview } from '@/lib/api/client'
import { cn } from '@/lib/utils'
import { useAuth } from './auth'
import { BrandHead, BrandIcon, Cloud, useBranding } from './branding'
import { ThemeToggle } from './theme-toggle'
import { UserMenu } from './user-menu'

interface NavItem {
  to: string
  label: string
  icon: IconType
}

const groups: { label: string; items: NavItem[]; admin?: boolean }[] = [
  {
    label: 'Monitoring',
    items: [
      { to: '/', label: 'Overview', icon: LuLayoutDashboard },
      { to: '/nodes', label: 'Nodes', icon: LuServer },
      { to: '/analytics', label: 'Analytics', icon: LuChartNoAxesColumn },
      { to: '/offenders', label: 'Offenders', icon: LuSiren },
    ],
  },
  {
    label: 'Configuration',
    items: [
      { to: '/profiles', label: 'Profiles', icon: LuSlidersHorizontal },
      { to: '/blocklist', label: 'Blocklist', icon: LuShieldBan },
      { to: '/upgrades', label: 'Upgrades', icon: LuPackageCheck },
    ],
  },
  { label: 'Compliance', items: [{ to: '/reports', label: 'Reports', icon: LuFileChartColumn }] },
  {
    label: 'Admin',
    admin: true,
    items: [
      { to: '/users', label: 'Users', icon: LuUsers },
      { to: '/audit', label: 'Audit', icon: LuScrollText },
      { to: '/settings', label: 'Settings', icon: LuSettings },
    ],
  },
]

// Active item: gold accent bar on the left edge plus the sidebar-accent highlight.
const activeBar =
  "relative data-[active=true]:bg-sidebar-accent data-[active=true]:before:absolute data-[active=true]:before:inset-y-1 data-[active=true]:before:left-0 data-[active=true]:before:w-[3px] data-[active=true]:before:rounded-r-full data-[active=true]:before:bg-brand-gold data-[active=true]:before:content-['']"

function NavEntry({ item }: { item: NavItem }) {
  const { isMobile, setOpenMobile } = useSidebar()
  const active = !!useMatch({ path: item.to, end: item.to === '/' })
  return (
    <SidebarMenuItem>
      <SidebarMenuButton asChild isActive={active} tooltip={item.label} className={activeBar}>
        <Link to={item.to} onClick={() => isMobile && setOpenMobile(false)}>
          <item.icon />
          <span>{item.label}</span>
        </Link>
      </SidebarMenuButton>
    </SidebarMenuItem>
  )
}

function Brand() {
  const { name, assets } = useBranding()
  return (
    <Link to="/" aria-label={`${name} home`} className="flex h-12 items-center gap-2 rounded-md px-1 outline-hidden focus-visible:ring-2 focus-visible:ring-sidebar-ring">
      <BrandIcon className={assets.navbar_dark ? 'hidden group-data-[collapsible=icon]:block' : ''} />
      {assets.navbar_dark ? (
        <img src={assets.navbar_dark} alt="" className="h-11 w-auto max-w-full object-contain object-left group-data-[collapsible=icon]:hidden" />
      ) : (
        <span className="truncate text-lg font-semibold tracking-tight group-data-[collapsible=icon]:hidden">{name}</span>
      )}
    </Link>
  )
}

/** x/y nodes online; amber when any node is degraded, red when any is offline. */
function FleetPill() {
  const { data } = useOverview()
  if (!data) return null
  const n = data.nodes
  const tone = n.offline
    ? 'border-red-400/40 bg-red-500/20 text-red-100 [--dot:var(--color-red-400)]'
    : n.degraded
      ? 'border-amber-300/40 bg-amber-400/15 text-amber-100 [--dot:var(--color-amber-300)]'
      : 'border-emerald-300/30 bg-emerald-400/10 text-emerald-50 [--dot:var(--color-emerald-400)]'
  return (
    <Link
      to="/nodes"
      className={cn(
        'flex items-center gap-1 rounded-full border px-2.5 py-1 text-xs font-medium whitespace-nowrap outline-hidden hover:brightness-125 focus-visible:ring-2 focus-visible:ring-brand-gold',
        tone,
      )}
    >
      <span aria-hidden className="mr-0.5 size-2 rounded-full bg-(--dot)" />
      <span className="tabular">
        {n.online ?? 0}/{data.nodes_total}
      </span>
      <span className="sr-only sm:not-sr-only">nodes online</span>
    </Link>
  )
}

/** Page title comes from the matched route's `handle.title` (see routes.tsx). */
function useTitle() {
  const m = useMatches()
  for (let i = m.length - 1; i >= 0; i--) {
    const t = (m[i].handle as { title?: string } | undefined)?.title
    if (t) return t
  }
  return ''
}

// Controls sitting on the navy top bar.
const onNavy = 'text-brand-navy-foreground hover:bg-white/10 hover:text-white dark:hover:bg-white/10 focus-visible:ring-brand-gold/60'

export function AppLayout() {
  const { isAdmin } = useAuth()
  const title = useTitle()
  return (
    <SidebarProvider>
      <BrandHead title={title} />
      <Sidebar collapsible="icon">
        <SidebarHeader className="border-b border-sidebar-border">
          <Brand />
        </SidebarHeader>
        <SidebarContent className="relative z-10">
          {groups
            .filter((g) => isAdmin || !g.admin)
            .map((g) => (
              <SidebarGroup key={g.label}>
                <SidebarGroupLabel className="text-brand-navy-muted">{g.label}</SidebarGroupLabel>
                <SidebarGroupContent>
                  <SidebarMenu>
                    {g.items.map((it) => (
                      <NavEntry key={it.to} item={it} />
                    ))}
                  </SidebarMenu>
                </SidebarGroupContent>
              </SidebarGroup>
            ))}
        </SidebarContent>
        <Cloud className="bottom-0 left-0 w-full opacity-15 group-data-[collapsible=icon]:hidden" />
        <SidebarRail />
      </Sidebar>
      <SidebarInset className="min-w-0">
        <header className="sticky top-0 z-20 flex h-12 shrink-0 items-center gap-2 overflow-hidden bg-brand-navy px-3 text-brand-navy-foreground shadow-sm">
          <Cloud className="top-1/2 right-0 w-64 -translate-y-1/2 opacity-15" />
          <SidebarTrigger className={cn('-ml-1', onNavy)} />
          <Separator orientation="vertical" className="mr-1 bg-white/20 data-[orientation=vertical]:h-4" />
          <h2 className="truncate text-sm font-medium">{title}</h2>
          <div className="relative ml-auto flex items-center gap-1">
            <FleetPill />
            <ThemeToggle className={onNavy} />
            <UserMenu className={onNavy} />
          </div>
        </header>
        {/* SidebarInset is already the <main> landmark */}
        <div className="mx-auto w-full max-w-[1600px] flex-1 space-y-6 p-4 md:p-6">
          <Outlet />
        </div>
      </SidebarInset>
    </SidebarProvider>
  )
}
