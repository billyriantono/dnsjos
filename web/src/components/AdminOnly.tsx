import type { ReactNode } from 'react'
import { LuLock } from 'react-icons/lu'

import { useAuth } from '@/app/auth'
import { EmptyState } from '@/components/EmptyState'
import { PageHeader } from '@/components/PageHeader'

/** Whole-page guard for admin-only pages (viewers get 403s from the API anyway). */
export function AdminOnly({ title, children }: { title: string; children: ReactNode }) {
  const { isAdmin } = useAuth()
  if (isAdmin) return children
  return (
    <>
      <PageHeader title={title} />
      <EmptyState icon={LuLock} title="Admins only" description="Your account is read-only. Ask an admin if you need access to this page." />
    </>
  )
}
