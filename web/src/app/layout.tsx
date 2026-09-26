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
import { useAuth } from './auth'
import { ThemeToggle } from './theme-toggle'
import { UserMenu } from './user-menu'

interface NavItem {
  to: string
  label: string
  icon: IconType
}

const monitor: NavItem[] = [
  { to: '/', label: 'Overview', icon: LuLayoutDashboard },
  { to: '/nodes', label: 'Nodes', icon: LuServer },
  { to: '/analytics', label: 'Analytics', icon: LuChartNoAxesColumn },
  { to: '/reports', label: 'Reports', icon: LuFileChartColumn },
  { to: '/offenders', label: 'Offenders', icon: LuSiren },
]
const fleet: NavItem[] = [{ to: '/upgrades', label: 'Upgrades', icon: LuPackageCheck }]
const configure: NavItem[] = [
  { to: '/profiles', label: 'Profiles', icon: LuSlidersHorizontal },
  { to: '/blocklist', label: 'Blocklist', icon: LuShieldBan },
]
const admin: NavItem[] = [
  { to: '/users', label: 'Users', icon: LuUsers },
  { to: '/audit', label: 'Audit log', icon: LuScrollText },
  { to: '/settings', label: 'Settings', icon: LuSettings },
]

function NavEntry({ item }: { item: NavItem }) {
  const { isMobile, setOpenMobile } = useSidebar()
  const active = !!useMatch({ path: item.to, end: item.to === '/' })
  return (
    <SidebarMenuItem>
      <SidebarMenuButton asChild isActive={active} tooltip={item.label}>
        <Link to={item.to} onClick={() => isMobile && setOpenMobile(false)}>
          <item.icon />
          <span>{item.label}</span>
        </Link>
      </SidebarMenuButton>
    </SidebarMenuItem>
  )
}

function NavGroup({ label, items }: { label: string; items: NavItem[] }) {
  return (
    <SidebarGroup>
      <SidebarGroupLabel>{label}</SidebarGroupLabel>
      <SidebarGroupContent>
        <SidebarMenu>
          {items.map((it) => (
            <NavEntry key={it.to} item={it} />
          ))}
        </SidebarMenu>
      </SidebarGroupContent>
    </SidebarGroup>
  )
}

function Brand() {
  return (
    <Link to="/" className="flex items-center gap-2 px-1 py-1.5">
      <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-primary text-sm font-bold text-primary-foreground">
        DJ
      </span>
      <span className="grid leading-tight group-data-[collapsible=icon]:hidden">
        <span className="font-semibold tracking-tight">DnsJos</span>
        <span className="text-xs text-muted-foreground">dnsdist fleet control</span>
      </span>
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

export function AppLayout() {
  const { isAdmin } = useAuth()
  const title = useTitle()
  return (
    <SidebarProvider>
      <Sidebar collapsible="icon" variant="inset">
        <SidebarHeader>
          <Brand />
        </SidebarHeader>
        <SidebarContent>
          <NavGroup label="Monitor" items={monitor} />
          <NavGroup label="Fleet" items={fleet} />
          <NavGroup label="Configure" items={configure} />
          {isAdmin && <NavGroup label="Admin" items={admin} />}
        </SidebarContent>
        <SidebarRail />
      </Sidebar>
      <SidebarInset className="min-w-0">
        <header className="sticky top-0 z-10 flex h-14 shrink-0 items-center gap-2 rounded-t-xl border-b bg-background/80 px-4 backdrop-blur">
          <SidebarTrigger className="-ml-1" />
          <Separator orientation="vertical" className="mr-1 data-[orientation=vertical]:h-4" />
          <h2 className="truncate text-sm font-medium">{title}</h2>
          <div className="ml-auto flex items-center gap-1">
            <ThemeToggle />
            <UserMenu />
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
