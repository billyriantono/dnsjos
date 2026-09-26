import type { ComponentType } from 'react'
import { createBrowserRouter, type RouteObject } from 'react-router'

import { Skeleton } from '@/components/ui/skeleton'
import LoginPage from '@/pages/LoginPage'
import { RequireAuth } from './auth'
import { AppLayout } from './layout'

// Pages are code-split; each page file default-exports its component. The static
// hydrate fallback shows inside the layout while the first page chunk loads (and
// silences React Router's missing-HydrateFallback warning).
const page = (load: () => Promise<{ default: ComponentType }>) => ({
  lazy: async () => ({ Component: (await load()).default }),
  hydrateFallbackElement: <Skeleton className="h-72" />,
})

// `handle.title` feeds the header title (layout.tsx). Admin-only pages are hidden from
// viewers in the nav; the API enforces the role either way.
const routes: RouteObject[] = [
  { path: '/login', element: <LoginPage /> },
  {
    element: <RequireAuth />,
    children: [
      {
        element: <AppLayout />,
        children: [
          { index: true, ...page(() => import('@/pages/overview/OverviewPage')), handle: { title: 'Overview' } },
          { path: 'nodes', ...page(() => import('@/pages/nodes/NodesPage')), handle: { title: 'Nodes' } },
          { path: 'nodes/:id', ...page(() => import('@/pages/nodes/NodeDetailPage')), handle: { title: 'Node' } },
          { path: 'upgrades', ...page(() => import('@/pages/upgrades/UpgradesPage')), handle: { title: 'Upgrades' } },
          { path: 'profiles', ...page(() => import('@/pages/profiles/ProfilesPage')), handle: { title: 'Profiles' } },
          { path: 'profiles/:id', ...page(() => import('@/pages/profiles/ProfileEditorPage')), handle: { title: 'Profile' } },
          { path: 'blocklist', ...page(() => import('@/pages/blocklist/BlocklistPage')), handle: { title: 'Blocklist' } },
          { path: 'analytics', ...page(() => import('@/pages/analytics/AnalyticsPage')), handle: { title: 'Analytics' } },
          { path: 'reports', ...page(() => import('@/pages/reports/ReportsPage')), handle: { title: 'Reports' } },
          { path: 'offenders', ...page(() => import('@/pages/offenders/OffendersPage')), handle: { title: 'Offenders' } },
          { path: 'users', ...page(() => import('@/pages/users/UsersPage')), handle: { title: 'Users' } },
          { path: 'audit', ...page(() => import('@/pages/audit/AuditPage')), handle: { title: 'Audit log' } },
          { path: 'settings', ...page(() => import('@/pages/settings/SettingsPage')), handle: { title: 'Settings' } },
          { path: '*', ...page(() => import('@/pages/NotFound')), handle: { title: 'Not found' } },
        ],
      },
    ],
  },
]

export const router = createBrowserRouter(routes)
