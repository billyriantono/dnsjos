import type { ComponentType } from 'react'
import { createBrowserRouter, type RouteObject } from 'react-router'

import LoginPage from '@/pages/LoginPage'
import { RequireAuth } from './auth'
import { AppLayout } from './layout'

// Pages are code-split; each page file default-exports its component.
const page = (load: () => Promise<{ default: ComponentType }>) => async () => ({ Component: (await load()).default })

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
          { index: true, lazy: page(() => import('@/pages/overview/OverviewPage')), handle: { title: 'Overview' } },
          { path: 'nodes', lazy: page(() => import('@/pages/nodes/NodesPage')), handle: { title: 'Nodes' } },
          { path: 'nodes/:id', lazy: page(() => import('@/pages/nodes/NodeDetailPage')), handle: { title: 'Node' } },
          { path: 'profiles', lazy: page(() => import('@/pages/profiles/ProfilesPage')), handle: { title: 'Profiles' } },
          { path: 'profiles/:id', lazy: page(() => import('@/pages/profiles/ProfileEditorPage')), handle: { title: 'Profile' } },
          { path: 'blocklist', lazy: page(() => import('@/pages/blocklist/BlocklistPage')), handle: { title: 'Blocklist' } },
          { path: 'reports', lazy: page(() => import('@/pages/reports/ReportsPage')), handle: { title: 'Reports' } },
          { path: 'offenders', lazy: page(() => import('@/pages/offenders/OffendersPage')), handle: { title: 'Offenders' } },
          { path: 'users', lazy: page(() => import('@/pages/users/UsersPage')), handle: { title: 'Users' } },
          { path: 'audit', lazy: page(() => import('@/pages/audit/AuditPage')), handle: { title: 'Audit log' } },
          { path: 'settings', lazy: page(() => import('@/pages/settings/SettingsPage')), handle: { title: 'Settings' } },
          { path: '*', lazy: page(() => import('@/pages/NotFound')), handle: { title: 'Not found' } },
        ],
      },
    ],
  },
]

export const router = createBrowserRouter(routes)
