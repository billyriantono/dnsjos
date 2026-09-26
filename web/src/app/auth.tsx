import { createContext, useContext, type ReactNode } from 'react'
import { Navigate, Outlet, useLocation } from 'react-router'

import { Skeleton } from '@/components/ui/skeleton'
import { useMe } from '@/lib/api/client'
import type { User } from '@/lib/api/types'

interface AuthState {
  user: User | null
  isAdmin: boolean
  loading: boolean
}

const AuthContext = createContext<AuthState>({ user: null, isAdmin: false, loading: true })

/** Resolves the session via GET /api/v1/auth/me. A 401 anywhere resets it (see api client). */
export function AuthProvider({ children }: { children: ReactNode }) {
  const { data, isPending } = useMe()
  const user = data ?? null
  return <AuthContext value={{ user, isAdmin: user?.role === 'admin', loading: isPending }}>{children}</AuthContext>
}

// eslint-disable-next-line react-refresh/only-export-components
export const useAuth = () => useContext(AuthContext)

/** Route guard: renders child routes when signed in, else redirects to /login?next=… */
export function RequireAuth() {
  const { user, loading } = useAuth()
  const loc = useLocation()
  if (loading)
    return (
      <div className="flex h-svh items-center justify-center">
        <Skeleton className="h-8 w-48" />
      </div>
    )
  if (!user) return <Navigate to={`/login?next=${encodeURIComponent(loc.pathname + loc.search)}`} replace />
  return <Outlet />
}

/**
 * Shows children only to admins (viewers are read-only, SPEC §10).
 * Wrap admin-only actions: `<RequireAdmin><Button>Delete</Button></RequireAdmin>`.
 */
export function RequireAdmin({ children, fallback = null }: { children: ReactNode; fallback?: ReactNode }) {
  return useAuth().isAdmin ? children : fallback
}
